// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"buf.build/gen/go/antinvestor/audit/connectrpc/go/v2/audit/v1/auditv1connect"
	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/handlers"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/antinvestor/service-authentication/apps/audit/tests"
	"github.com/pitabwire/frame/v3/security"
	"github.com/pitabwire/frame/v3/tenancy"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

type HandlerSuite struct {
	tests.BaseTestSuite
}

func TestHandlerSuite(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

// Test headers carrying the identity the auth interceptor would derive
// from a JWT in production.
const (
	hdrTenant  = "X-Test-Tenant"
	hdrProfile = "X-Test-Profile"
	hdrSA      = "X-Test-Service-Account"
	hdrService = "X-Test-Service-Name"
	hdrAny     = "X-Test-Create-Any"
)

// claimsInjector replaces the auth interceptor: it turns test headers into
// Frame claims so the handler, RLS binding and permission resolver behave
// as in production.
type claimsInjector struct{}

func (claimsInjector) inject(ctx context.Context, h *connect.Header) context.Context {
	if h.Get(hdrTenant) == "" {
		return ctx
	}
	claims := &security.AuthenticationClaims{
		TenantID: h.Get(hdrTenant), PartitionID: "p-" + h.Get(hdrTenant), ProfileID: h.Get(hdrProfile),
		ServiceName: h.Get(hdrService), Roles: []string{"user"}, Ext: map[string]any{},
	}
	claims.Subject = claims.ProfileID
	if sa := h.Get(hdrSA); sa != "" {
		claims.Ext["service_account_id"] = sa
		claims.Roles = []string{"system_internal"}
	}
	if h.Get(hdrAny) == "1" {
		claims.Ext["create_any"] = true
	}
	return claims.ClaimsToContext(ctx)
}

func (c claimsInjector) interceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if info, ok := connect.CallInfoForServerContext(ctx); ok {
				ctx = c.inject(ctx, info.RequestHeader())
			}
			return next(ctx, spec, stream)
		}
	}
}

// createAnyResolver grants audit_create_any when the test header asked for it.
type createAnyResolver struct{}

func (createAnyResolver) Check(ctx context.Context, permission string) error {
	claims := security.ClaimsFromContext(ctx)
	if permission == business.PermissionCreateAny && claims != nil {
		if v, ok := claims.Ext["create_any"].(bool); ok && v {
			return nil
		}
	}
	return connect.NewError(connect.CodePermissionDenied, "")
}

type env struct {
	svc    *tests.Service
	deps   *handlers.Deps
	server *httptest.Server
	client auditv1connect.AuditServiceClient
}

func (s *HandlerSuite) newEnv() *env {
	t := s.T()
	svc := s.CreateService(t, nil)
	keys, err := business.NewKeyProvider(svc.Ctx, svc.Cfg, repository.NewSigningKeyRepository(svc.Ctx, svc.Pool))
	s.Require().NoError(err)
	s.Require().NoError(keys.Seed(tests.GlobalContext(svc.Ctx)))
	deps := handlers.BuildDeps(svc.Ctx, svc.Cfg, tests.NamespaceAudit, svc.Pool, keys)

	impl := handlers.NewAuditServer(deps, createAnyResolver{})
	rpc := connect.NewServer(claimsInjector{}.interceptor(), tenancy.NewClaimsInterceptor())
	auditv1connect.RegisterAuditServiceHandler(rpc, impl)
	mux := http.NewServeMux()
	mux.Handle(handlers.WellKnownKeysPath, handlers.WellKnownKeysHandler(keys, tests.NamespaceAudit))
	connecthttp.Mount(mux, rpc)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &env{svc: svc, deps: deps, server: server,
		client: auditv1connect.NewAuditServiceClient(connect.NewClient(connecthttp.NewTransport(server.Client(), server.URL)))}
}

// callAs returns a client context carrying the test identity headers, and
// the call info for adding more headers or reading response metadata.
func callAs(ctx context.Context, tenant, profile, service string) (context.Context, *connect.CallInfo) {
	ctx, info := connect.NewClientContext(ctx)
	info.RequestHeader().Set(hdrTenant, tenant)
	info.RequestHeader().Set(hdrProfile, profile)
	info.RequestHeader().Set(hdrService, service)
	return ctx, info
}

func asUser(ctx context.Context, tenant, profile, service string) context.Context {
	ctx, _ = callAs(ctx, tenant, profile, service)
	return ctx
}

func asServiceAccount(ctx context.Context, tenant, saProfile, saID, service string) context.Context {
	ctx, info := callAs(ctx, tenant, saProfile, service)
	info.RequestHeader().Set(hdrSA, saID)
	return ctx
}

func createReq(entryID string) *auditv1.CreateAuditEntryRequest {
	m := &auditv1.CreateAuditEntryRequest{}
	m.SetProfileId("person-1")
	m.SetAction("create")
	m.SetResourceType("loan")
	m.SetResourceId("loan-1")
	m.SetService("service_loans")
	m.SetEntryId(entryID)
	return m
}

func (s *HandlerSuite) drain(e *env) {
	for range 50 {
		stats, err := e.deps.Writer.Tick(e.svc.Ctx)
		s.Require().NoError(err)
		if stats.Committed == 0 && stats.Failed == 0 {
			return
		}
	}
	s.FailNow("writer did not drain")
}

func (s *HandlerSuite) TestCreate_AcceptsPersonAndIsIdempotent() {
	e := s.newEnv()
	ctx := s.T().Context()

	resp, err := e.client.CreateAuditEntry(asUser(ctx, "t-h", "person-1", "service_loans"), createReq("h-1"))
	s.Require().NoError(err)
	s.Require().Equal(auditv1.IntakeState_INTAKE_STATE_ACCEPTED, resp.GetState())
	s.Require().NotEmpty(resp.GetIntakeId())

	again, err := e.client.CreateAuditEntry(asUser(ctx, "t-h", "person-1", "service_loans"), createReq("h-1"))
	s.Require().NoError(err)
	s.Require().Equal(resp.GetIntakeId(), again.GetIntakeId())

	s.drain(e)

	after, err := e.client.CreateAuditEntry(asUser(ctx, "t-h", "person-1", "service_loans"), createReq("h-1"))
	s.Require().NoError(err)
	s.Require().Equal(auditv1.IntakeState_INTAKE_STATE_COMMITTED, after.GetState(), "duplicate after commit reports the committed state")

	list, err := e.client.ListAuditEntries(asUser(ctx, "t-h", "person-1", "service_loans"), func() *auditv1.ListAuditEntriesRequest {
		r := &auditv1.ListAuditEntriesRequest{}
		r.SetSeqFrom(1)
		return r
	}())
	s.Require().NoError(err)
	first, err := list.Receive()
	s.Require().NoError(err)
	entries := first.GetData()
	s.Require().Len(entries, 1)
	s.Require().Equal(int64(1), entries[0].GetSeq())
	s.Require().Equal("k1", entries[0].GetKeyId())
	s.Require().Equal(auditv1.IntakeState_INTAKE_STATE_COMMITTED, entries[0].GetState())

	got, err := e.client.GetAuditEntry(asUser(ctx, "t-h", "person-1", "service_loans"), func() *auditv1.GetAuditEntryRequest {
		r := &auditv1.GetAuditEntryRequest{}
		r.SetId(entries[0].GetId())
		return r
	}())
	s.Require().NoError(err)
	s.Require().Equal("h-1", got.GetData().GetEntryId())
}

func (s *HandlerSuite) TestCreate_RejectionsMapToConnectCodes() {
	e := s.newEnv()
	ctx := s.T().Context()

	asSA := func(ctx context.Context) (context.Context, *connect.CallInfo) {
		ctx, info := callAs(ctx, "t-r", "sa-profile", "service_loans")
		info.RequestHeader().Set(hdrSA, "sa-1")
		return ctx, info
	}
	cases := []struct {
		name     string
		req      *auditv1.CreateAuditEntryRequest
		as       func(context.Context) (context.Context, *connect.CallInfo)
		wantCode connect.Code
		reason   string
	}{
		{"service binding", createReq("r-1"), func(ctx context.Context) (context.Context, *connect.CallInfo) {
			return callAs(ctx, "t-r", "person-1", "service_other")
		}, connect.CodePermissionDenied, business.ReasonServiceBinding},
		{"service account without on_behalf_of", func() *auditv1.CreateAuditEntryRequest {
			r := createReq("r-2")
			r.SetProfileId("sa-profile")
			return r
		}(), asSA, connect.CodeInvalidArgument, business.ReasonActor},
		{"unauthenticated", createReq("r-3"), connect.NewClientContext, connect.CodeInvalidArgument, business.ReasonActor},
		{"forbidden content", func() *auditv1.CreateAuditEntryRequest {
			r := createReq("r-4")
			r.SetPayloadHash("zz")
			return r
		}(), func(ctx context.Context) (context.Context, *connect.CallInfo) {
			return callAs(ctx, "t-r", "person-1", "service_loans")
		}, connect.CodeInvalidArgument, business.ReasonHash},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			callCtx, info := tc.as(ctx)
			_, err := e.client.CreateAuditEntry(callCtx, tc.req)
			s.Require().Error(err)
			s.Require().Equal(tc.wantCode, connect.CodeOf(err))
			s.Require().Equal(tc.reason, info.ResponseHeader().Get("Audit-Reject-Reason"))
		})
	}

	// create_any lets the audit operator log under another service, and a
	// service account acting for a person is accepted.
	r := createReq("r-5")
	r.SetService("service_other")
	anyCtx, anyInfo := callAs(ctx, "t-r", "operator", "service_audit")
	anyInfo.RequestHeader().Set(hdrAny, "1")
	_, err := e.client.CreateAuditEntry(anyCtx, r)
	s.Require().NoError(err)

	obo := createReq("r-6")
	obo.SetProfileId("person-2")
	obo.SetOnBehalfOf("person-2")
	_, err = e.client.CreateAuditEntry(asServiceAccount(ctx, "t-r", "sa-profile", "sa-1", "service_loans"), obo)
	s.Require().NoError(err)
}

func (s *HandlerSuite) TestManifest_RegisterGetAndVerifyExport() {
	e := s.newEnv()
	ctx := s.T().Context()

	m := &auditv1.AuditManifest{}
	m.SetService("service_loans")
	m.SetActions([]string{"create"})
	m.SetResourceTypes([]string{"loan"})
	reg := &auditv1.RegisterAuditManifestRequest{}
	reg.SetManifest(m)
	res, err := e.client.RegisterAuditManifest(asServiceAccount(ctx, "t-m", "sa-loans", "sa-1", "service_loans"), reg)
	s.Require().NoError(err)
	s.Require().Equal(int32(1), res.GetVersion())

	_, err = e.client.RegisterAuditManifest(asServiceAccount(ctx, "t-m", "sa-other", "sa-2", "service_other"), reg)
	s.Require().Equal(connect.CodePermissionDenied, connect.CodeOf(err))

	get := &auditv1.GetAuditManifestRequest{}
	get.SetService("service_loans")
	got, err := e.client.GetAuditManifest(asUser(ctx, "t-m", "person-1", "service_loans"), get)
	s.Require().NoError(err)
	s.Require().Equal([]string{"create"}, got.GetManifest().GetActions())

	// Vocabulary is enforced through the RPC.
	bad := createReq("m-bad")
	bad.SetAction("approve")
	_, err = e.client.CreateAuditEntry(asUser(ctx, "t-m", "person-1", "service_loans"), bad)
	s.Require().Equal(connect.CodeInvalidArgument, connect.CodeOf(err))

	batch := &auditv1.BatchCreateAuditEntriesRequest{}
	items := make([]*auditv1.CreateAuditEntryRequest, 0, 5)
	for i := range 5 {
		item := createReq("m-" + string(rune('a'+i)))
		details, derr := structpb.NewStruct(map[string]any{"amount": 1.5, "count": float64(i), "note": "ok", "nested": map[string]any{"flag": true}})
		s.Require().NoError(derr)
		item.SetDetails(details)
		items = append(items, item)
	}
	batch.SetEntries(items)
	bresp, err := e.client.BatchCreateAuditEntries(asUser(ctx, "t-m", "person-1", "service_loans"), batch)
	s.Require().NoError(err)
	s.Require().Len(bresp.GetReceipts(), 5)
	s.drain(e)

	verify := &auditv1.VerifyIntegrityRequest{}
	vresp, err := e.client.VerifyIntegrity(asUser(ctx, "t-m", "person-1", "service_loans"), verify)
	s.Require().NoError(err)
	s.Require().True(vresp.GetValid(), vresp.GetMessage())
	s.Require().Equal(int64(5), vresp.GetEntriesVerified())
	s.Require().Equal([]string{"k1"}, vresp.GetKeyIdsUsed())

	exp := &auditv1.ExportAuditEntriesRequest{}
	exp.SetStartSeq(2)
	exp.SetEndSeq(4)
	stream, err := e.client.ExportAuditEntries(asUser(ctx, "t-m", "person-1", "service_loans"), exp)
	s.Require().NoError(err)
	var seqs []int64
	var headerSeen bool
	var pub ed25519.PublicKey
	var streamErr error
	for {
		msg, recvErr := stream.Receive()
		if recvErr != nil {
			streamErr = recvErr
			break
		}
		if h := msg.GetHeader(); h != nil {
			headerSeen = true
			s.Require().Equal("t-m", h.GetTenantId())
			s.Require().Len(h.GetKeys(), 1)
			raw, herr := hex.DecodeString(h.GetKeys()[0].GetPublicKey())
			s.Require().NoError(herr)
			pub = ed25519.PublicKey(raw)
			continue
		}
		entry := msg.GetEntry()
		seqs = append(seqs, entry.GetSeq())
		// The exported wire form carries everything an offline verifier
		// needs: rebuilding the model from it reproduces the stored hash.
		s.Require().Equal(1.5, entry.GetDetails().AsMap()["amount"])
		rebuilt := modelFromProto(entry)
		recomputed, herr := business.EntryHash(rebuilt, entry.GetPreviousHash())
		s.Require().NoError(herr)
		s.Require().Equal(entry.GetEntryHash(), recomputed)
		s.Require().True(business.VerifyHash(pub, entry.GetEntryHash(), entry.GetSignature(), int16(entry.GetCanonVersion())))
	}
	if errors.Is(streamErr, io.EOF) {
		streamErr = nil
	}
	s.Require().NoError(streamErr)
	s.Require().True(headerSeen)
	s.Require().Equal([]int64{2, 3, 4}, seqs)

	// Tenant isolation: another tenant sees an empty chain.
	other, err := e.client.VerifyIntegrity(asUser(ctx, "t-x", "person-9", "service_loans"), &auditv1.VerifyIntegrityRequest{})
	s.Require().NoError(err)
	s.Require().Zero(other.GetEntriesVerified())

	cps, err := e.client.ListCheckpoints(asUser(ctx, "t-m", "person-1", "service_loans"), &auditv1.ListCheckpointsRequest{})
	s.Require().NoError(err)
	s.Require().Len(cps.GetData(), 1, "first batch always checkpoints (interval rule)")
	s.Require().Equal(int64(5), cps.GetData()[0].GetSeq())
}

func (s *HandlerSuite) TestOperations_RetireKeyAndWellKnownKeys() {
	e := s.newEnv()
	ctx := s.T().Context()

	resp, err := e.server.Client().Get(e.server.URL + handlers.WellKnownKeysPath)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	s.Require().Equal("public, max-age=300", resp.Header.Get("Cache-Control"))
	var doc struct {
		Keys []struct {
			KeyID     string     `json:"key_id"`
			PublicKey string     `json:"public_key_hex"`
			RetiredAt *time.Time `json:"retired_at"`
		} `json:"keys"`
	}
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&doc))
	s.Require().Len(doc.Keys, 1)
	s.Require().Equal("k1", doc.Keys[0].KeyID)
	s.Require().Len(doc.Keys[0].PublicKey, 64)
	s.Require().Nil(doc.Keys[0].RetiredAt)

	keysResp, err := e.client.GetSigningKeys(asUser(ctx, "t-o", "person-1", "service_loans"), &auditv1.GetSigningKeysRequest{})
	s.Require().NoError(err)
	s.Require().Len(keysResp.GetData(), 1)

	retire := &auditv1.RetireSigningKeyRequest{}
	retire.SetKeyId("k1")
	rresp, err := e.client.RetireSigningKey(asUser(ctx, "t-o", "operator", "service_audit"), retire)
	s.Require().NoError(err)
	s.Require().NotNil(rresp.GetKey().GetRetiredAt())

	_, err = e.client.RetireSigningKey(asUser(ctx, "t-o", "operator", "service_audit"), retire)
	s.Require().Equal(connect.CodeNotFound, connect.CodeOf(err))

	// The operator action was itself queued for the chain under service_audit.
	var self int64
	s.Require().NoError(e.svc.Pool.DB(tests.GlobalContext(e.svc.Ctx), true).Table("audit_intake").
		Where("service = ? AND tenant_id = ?", "service_audit", "t-o").Count(&self).Error)
	s.Require().Equal(int64(1), self)

	s.Require().Error(e.deps.Writer.ReadinessChecker().CheckHealth(), "retired active key fails readiness")
}

// modelFromProto mirrors what common/auditverify does with an exported entry.
func modelFromProto(o *auditv1.AuditEntryObject) *models.AuditEntry {
	e := &models.AuditEntry{
		ProfileID: o.GetProfileId(), Action: o.GetAction(), ResourceType: o.GetResourceType(), ResourceID: o.GetResourceId(),
		Service: o.GetService(), IPAddress: o.GetIpAddress(), UserAgent: o.GetUserAgent(), DeviceID: o.GetDeviceId(),
		TargetProfileID: o.GetTargetProfileId(), TraceID: o.GetTraceId(), Seq: o.GetSeq(), CanonVersion: int16(o.GetCanonVersion()),
		EntryID: o.GetEntryId(), ActorServiceAccountID: o.GetActorServiceAccountId(), OnBehalfOf: o.GetOnBehalfOf(),
		OccurredAt: o.GetOccurredAt().AsTime(), ReceivedAt: o.GetReceivedAt().AsTime(), ManifestVersion: o.GetManifestVersion(),
		CorrelationID: o.GetCorrelationId(), EventID: o.GetEventId(), IntentID: o.GetIntentId(), InstanceID: o.GetInstanceId(),
		PayloadHash: o.GetPayloadHash(), AuthorizationHash: o.GetAuthorizationHash(), PolicyHash: o.GetPolicyHash(),
		DeviceKeyID: o.GetDeviceKeyId(), StateFrom: o.GetStateFrom(), StateTo: o.GetStateTo(), ResourceVersion: o.GetResourceVersion(),
		OutcomeOfEntryID: o.GetOutcomeOfEntryId(), AuditClass: o.GetAuditClass(),
		WrittenDuringDegradation: o.GetWrittenDuringDegradation(),
	}
	switch o.GetPhase() {
	case auditv1.AuditPhase_AUDIT_PHASE_REQUESTED:
		e.Phase = models.PhaseRequested
	case auditv1.AuditPhase_AUDIT_PHASE_COMPLETED:
		e.Phase = models.PhaseCompleted
	case auditv1.AuditPhase_AUDIT_PHASE_FAILED:
		e.Phase = models.PhaseFailed
	case auditv1.AuditPhase_AUDIT_PHASE_UNSPECIFIED:
	}
	e.TenantID, e.PartitionID = o.GetTenantId(), o.GetPartitionId()
	e.CreatedAt = o.GetCreatedAt().AsTime()
	if o.GetDetails() != nil {
		e.Details = o.GetDetails().AsMap()
	}
	if rels := o.GetRelations(); len(rels) > 0 {
		items := make([]any, 0, len(rels))
		for _, r := range rels {
			items = append(items, map[string]any{"parent_type": r.GetParentType(), "parent_id": r.GetParentId(),
				"child_type": r.GetChildType(), "child_id": r.GetChildId(), "action": r.GetAction()})
		}
		e.Relations = map[string]any{"items": items}
	}
	return e
}

func (s *HandlerSuite) TestSearch_RequiresWindow() {
	e := s.newEnv()
	ctx := s.T().Context()
	q := &auditv1.SearchAuditEntriesRequest{}
	q.SetQuery("cre")
	stream, err := e.client.SearchAuditEntries(asUser(ctx, "t-s", "person-1", "service_loans"), q)
	s.Require().NoError(err)
	_, err = stream.Receive()
	s.Require().Equal(connect.CodeInvalidArgument, connect.CodeOf(err))
}
