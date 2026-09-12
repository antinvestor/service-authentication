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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"buf.build/gen/go/antinvestor/audit/connectrpc/go/audit/v1/auditv1connect"
	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/handlers"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/antinvestor/service-authentication/apps/audit/tests"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/tenancy"
	"github.com/stretchr/testify/suite"
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

func (claimsInjector) inject(ctx context.Context, h http.Header) context.Context {
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

func (c claimsInjector) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		return next(c.inject(ctx, req.Header()), req)
	}
}

func (claimsInjector) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (c claimsInjector) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return next(c.inject(ctx, conn.RequestHeader()), conn)
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
	return connect.NewError(connect.CodePermissionDenied, nil)
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
	_, h := auditv1connect.NewAuditServiceHandler(impl, connect.WithInterceptors(claimsInjector{}, tenancy.NewClaimsInterceptor()))
	mux := http.NewServeMux()
	mux.Handle(handlers.WellKnownKeysPath, handlers.WellKnownKeysHandler(keys, tests.NamespaceAudit))
	mux.Handle("/", h)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &env{svc: svc, deps: deps, server: server,
		client: auditv1connect.NewAuditServiceClient(server.Client(), server.URL)}
}

func asUser[T any](req *connect.Request[T], tenant, profile, service string) *connect.Request[T] {
	req.Header().Set(hdrTenant, tenant)
	req.Header().Set(hdrProfile, profile)
	req.Header().Set(hdrService, service)
	return req
}

func asServiceAccount[T any](req *connect.Request[T], tenant, saProfile, saID, service string) *connect.Request[T] {
	asUser(req, tenant, saProfile, service)
	req.Header().Set(hdrSA, saID)
	return req
}

func createReq(entryID string) *connect.Request[auditv1.CreateAuditEntryRequest] {
	m := &auditv1.CreateAuditEntryRequest{}
	m.SetProfileId("person-1")
	m.SetAction("create")
	m.SetResourceType("loan")
	m.SetResourceId("loan-1")
	m.SetService("service_loans")
	m.SetEntryId(entryID)
	return connect.NewRequest(m)
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

	resp, err := e.client.CreateAuditEntry(ctx, asUser(createReq("h-1"), "t-h", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Equal(auditv1.IntakeState_INTAKE_STATE_ACCEPTED, resp.Msg.GetState())
	s.Require().NotEmpty(resp.Msg.GetIntakeId())

	again, err := e.client.CreateAuditEntry(ctx, asUser(createReq("h-1"), "t-h", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Equal(resp.Msg.GetIntakeId(), again.Msg.GetIntakeId())

	s.drain(e)

	after, err := e.client.CreateAuditEntry(ctx, asUser(createReq("h-1"), "t-h", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Equal(auditv1.IntakeState_INTAKE_STATE_COMMITTED, after.Msg.GetState(), "duplicate after commit reports the committed state")

	list, err := e.client.ListAuditEntries(ctx, asUser(connect.NewRequest(func() *auditv1.ListAuditEntriesRequest {
		r := &auditv1.ListAuditEntriesRequest{}
		r.SetSeqFrom(1)
		return r
	}()), "t-h", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().True(list.Receive())
	entries := list.Msg().GetData()
	s.Require().Len(entries, 1)
	s.Require().Equal(int64(1), entries[0].GetSeq())
	s.Require().Equal("k1", entries[0].GetKeyId())
	s.Require().Equal(auditv1.IntakeState_INTAKE_STATE_COMMITTED, entries[0].GetState())

	got, err := e.client.GetAuditEntry(ctx, asUser(connect.NewRequest(func() *auditv1.GetAuditEntryRequest {
		r := &auditv1.GetAuditEntryRequest{}
		r.SetId(entries[0].GetId())
		return r
	}()), "t-h", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Equal("h-1", got.Msg.GetData().GetEntryId())
}

func (s *HandlerSuite) TestCreate_RejectionsMapToConnectCodes() {
	e := s.newEnv()
	ctx := s.T().Context()

	cases := []struct {
		name     string
		req      *connect.Request[auditv1.CreateAuditEntryRequest]
		wantCode connect.Code
		reason   string
	}{
		{"service binding", asUser(createReq("r-1"), "t-r", "person-1", "service_other"), connect.CodePermissionDenied, business.ReasonServiceBinding},
		{"service account without on_behalf_of", func() *connect.Request[auditv1.CreateAuditEntryRequest] {
			r := createReq("r-2")
			r.Msg.SetProfileId("sa-profile")
			return asServiceAccount(r, "t-r", "sa-profile", "sa-1", "service_loans")
		}(), connect.CodeInvalidArgument, business.ReasonActor},
		{"unauthenticated", createReq("r-3"), connect.CodeInvalidArgument, business.ReasonActor},
		{"forbidden content", func() *connect.Request[auditv1.CreateAuditEntryRequest] {
			r := createReq("r-4")
			r.Msg.SetPayloadHash("zz")
			return asUser(r, "t-r", "person-1", "service_loans")
		}(), connect.CodeInvalidArgument, business.ReasonHash},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			_, err := e.client.CreateAuditEntry(ctx, tc.req)
			s.Require().Error(err)
			s.Require().Equal(tc.wantCode, connect.CodeOf(err))
			var cerr *connect.Error
			s.Require().ErrorAs(err, &cerr)
			s.Require().Equal(tc.reason, cerr.Meta().Get("Audit-Reject-Reason"))
		})
	}

	// create_any lets the audit operator log under another service, and a
	// service account acting for a person is accepted.
	r := createReq("r-5")
	r.Msg.SetService("service_other")
	req := asUser(r, "t-r", "operator", "service_audit")
	req.Header().Set(hdrAny, "1")
	_, err := e.client.CreateAuditEntry(ctx, req)
	s.Require().NoError(err)

	obo := createReq("r-6")
	obo.Msg.SetProfileId("person-2")
	obo.Msg.SetOnBehalfOf("person-2")
	_, err = e.client.CreateAuditEntry(ctx, asServiceAccount(obo, "t-r", "sa-profile", "sa-1", "service_loans"))
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
	res, err := e.client.RegisterAuditManifest(ctx, asServiceAccount(connect.NewRequest(reg), "t-m", "sa-loans", "sa-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Equal(int32(1), res.Msg.GetVersion())

	_, err = e.client.RegisterAuditManifest(ctx, asServiceAccount(connect.NewRequest(reg), "t-m", "sa-other", "sa-2", "service_other"))
	s.Require().Equal(connect.CodePermissionDenied, connect.CodeOf(err))

	get := &auditv1.GetAuditManifestRequest{}
	get.SetService("service_loans")
	got, err := e.client.GetAuditManifest(ctx, asUser(connect.NewRequest(get), "t-m", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Equal([]string{"create"}, got.Msg.GetManifest().GetActions())

	// Vocabulary is enforced through the RPC.
	bad := createReq("m-bad")
	bad.Msg.SetAction("approve")
	_, err = e.client.CreateAuditEntry(ctx, asUser(bad, "t-m", "person-1", "service_loans"))
	s.Require().Equal(connect.CodeInvalidArgument, connect.CodeOf(err))

	batch := &auditv1.BatchCreateAuditEntriesRequest{}
	items := make([]*auditv1.CreateAuditEntryRequest, 0, 5)
	for i := range 5 {
		items = append(items, createReq("m-"+string(rune('a'+i))).Msg)
	}
	batch.SetEntries(items)
	bresp, err := e.client.BatchCreateAuditEntries(ctx, asUser(connect.NewRequest(batch), "t-m", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Len(bresp.Msg.GetReceipts(), 5)
	s.drain(e)

	verify := &auditv1.VerifyIntegrityRequest{}
	vresp, err := e.client.VerifyIntegrity(ctx, asUser(connect.NewRequest(verify), "t-m", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().True(vresp.Msg.GetValid(), vresp.Msg.GetMessage())
	s.Require().Equal(int64(5), vresp.Msg.GetEntriesVerified())
	s.Require().Equal([]string{"k1"}, vresp.Msg.GetKeyIdsUsed())

	exp := &auditv1.ExportAuditEntriesRequest{}
	exp.SetStartSeq(2)
	exp.SetEndSeq(4)
	stream, err := e.client.ExportAuditEntries(ctx, asUser(connect.NewRequest(exp), "t-m", "person-1", "service_loans"))
	s.Require().NoError(err)
	var seqs []int64
	var headerSeen bool
	for stream.Receive() {
		msg := stream.Msg()
		if h := msg.GetHeader(); h != nil {
			headerSeen = true
			s.Require().Equal("t-m", h.GetTenantId())
			s.Require().Len(h.GetKeys(), 1)
			continue
		}
		seqs = append(seqs, msg.GetEntry().GetSeq())
	}
	s.Require().NoError(stream.Err())
	s.Require().True(headerSeen)
	s.Require().Equal([]int64{2, 3, 4}, seqs)

	// Tenant isolation: another tenant sees an empty chain.
	other, err := e.client.VerifyIntegrity(ctx, asUser(connect.NewRequest(&auditv1.VerifyIntegrityRequest{}), "t-x", "person-9", "service_loans"))
	s.Require().NoError(err)
	s.Require().Zero(other.Msg.GetEntriesVerified())

	cps, err := e.client.ListCheckpoints(ctx, asUser(connect.NewRequest(&auditv1.ListCheckpointsRequest{}), "t-m", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Len(cps.Msg.GetData(), 1, "first batch always checkpoints (interval rule)")
	s.Require().Equal(int64(5), cps.Msg.GetData()[0].GetSeq())
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

	keysResp, err := e.client.GetSigningKeys(ctx, asUser(connect.NewRequest(&auditv1.GetSigningKeysRequest{}), "t-o", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().Len(keysResp.Msg.GetData(), 1)

	retire := &auditv1.RetireSigningKeyRequest{}
	retire.SetKeyId("k1")
	rresp, err := e.client.RetireSigningKey(ctx, asUser(connect.NewRequest(retire), "t-o", "operator", "service_audit"))
	s.Require().NoError(err)
	s.Require().NotNil(rresp.Msg.GetKey().GetRetiredAt())

	_, err = e.client.RetireSigningKey(ctx, asUser(connect.NewRequest(retire), "t-o", "operator", "service_audit"))
	s.Require().Equal(connect.CodeNotFound, connect.CodeOf(err))

	// The operator action was itself queued for the chain under service_audit.
	var self int64
	s.Require().NoError(e.svc.Pool.DB(tests.GlobalContext(e.svc.Ctx), true).Table("audit_intake").
		Where("service = ? AND tenant_id = ?", "service_audit", "t-o").Count(&self).Error)
	s.Require().Equal(int64(1), self)

	s.Require().Error(e.deps.Writer.ReadinessChecker().CheckHealth(), "retired active key fails readiness")
}

func (s *HandlerSuite) TestSearch_RequiresWindow() {
	e := s.newEnv()
	ctx := s.T().Context()
	q := &auditv1.SearchAuditEntriesRequest{}
	q.SetQuery("cre")
	stream, err := e.client.SearchAuditEntries(ctx, asUser(connect.NewRequest(q), "t-s", "person-1", "service_loans"))
	s.Require().NoError(err)
	s.Require().False(stream.Receive())
	s.Require().Equal(connect.CodeInvalidArgument, connect.CodeOf(stream.Err()))
}
