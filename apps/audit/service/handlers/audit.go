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

package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"buf.build/gen/go/antinvestor/audit/connectrpc/go/audit/v1/auditv1connect"
	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PermissionResolver answers whether the caller holds a named permission.
// Frame's authorizer.FunctionChecker satisfies it.
type PermissionResolver interface {
	Check(ctx context.Context, permission string) error
}

// Deps are the wired business components.
type Deps struct {
	Ingest    business.IngestBusiness
	Read      business.ReadBusiness
	Verify    business.VerifyBusiness
	Manifests business.ManifestBusiness
	Keys      business.KeyProvider
	Writer    *business.Writer
	Metrics   *business.Metrics
}

// BuildDeps wires repositories and business layers on a pool.
func BuildDeps(ctx context.Context, cfg *aconfig.AuditConfig, serviceName string, dbPool pool.Pool, keys business.KeyProvider) *Deps {
	entries := repository.NewAuditEntryRepository(dbPool)
	intake := repository.NewIntakeRepository(ctx, dbPool)
	rejections := repository.NewRejectionRepository(ctx, dbPool)
	checkpoints := repository.NewCheckpointRepository(dbPool)
	heads := repository.NewChainHeadRepository(dbPool)
	manifestRepo := repository.NewManifestRepository(ctx, dbPool)
	chain := repository.NewChainRepository(dbPool)

	metrics := business.NewMetrics()
	manifests := business.NewManifestBusiness(manifestRepo)
	validator := business.NewValidator(manifests.Lookup, cfg.RequireManifest)
	writer := business.NewWriter(cfg, serviceName, business.WriterRepos{
		Chain: chain, Intake: intake, Rejections: rejections, Checkpoints: checkpoints,
	}, keys, metrics)

	return &Deps{
		Ingest:    business.NewIngestBusiness(cfg, validator, intake, rejections, metrics),
		Read:      business.NewReadBusiness(entries, checkpoints, heads),
		Verify:    business.NewVerifyBusiness(cfg, entries, checkpoints, heads, keys, metrics),
		Manifests: manifests,
		Keys:      keys,
		Writer:    writer,
		Metrics:   metrics,
	}
}

// AuditServer implements the generated AuditServiceHandler.
type AuditServer struct {
	deps        *Deps
	permissions PermissionResolver
	auditv1connect.UnimplementedAuditServiceHandler
}

// NewAuditServer creates the Connect handler. permissions may be nil (then
// audit_create_any is never granted).
func NewAuditServer(deps *Deps, permissions PermissionResolver) *AuditServer {
	return &AuditServer{deps: deps, permissions: permissions}
}

func (as *AuditServer) caller(ctx context.Context) business.Caller {
	c := business.CallerFromClaims(ctx)
	if as.permissions != nil && as.permissions.Check(ctx, business.PermissionCreateAny) == nil {
		c.CanCreateAny = true
	}
	return c
}

// CreateAuditEntry validates and durably accepts one entry.
func (as *AuditServer) CreateAuditEntry(ctx context.Context, req *connect.Request[auditv1.CreateAuditEntryRequest]) (*connect.Response[auditv1.CreateAuditEntryResponse], error) {
	receipt, err := as.deps.Ingest.Create(ctx, as.caller(ctx), req.Msg)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(receiptToProto(receipt)), nil
}

// BatchCreateAuditEntries validates and accepts a batch as a whole.
func (as *AuditServer) BatchCreateAuditEntries(ctx context.Context, req *connect.Request[auditv1.BatchCreateAuditEntriesRequest]) (*connect.Response[auditv1.BatchCreateAuditEntriesResponse], error) {
	receipts, err := as.deps.Ingest.CreateBatch(ctx, as.caller(ctx), req.Msg.GetEntries())
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*auditv1.CreateAuditEntryResponse, 0, len(receipts))
	for _, r := range receipts {
		out = append(out, receiptToProto(r))
	}
	resp := &auditv1.BatchCreateAuditEntriesResponse{}
	resp.SetReceipts(out)
	return connect.NewResponse(resp), nil
}

// GetAuditEntry retrieves a chained entry by ID.
func (as *AuditServer) GetAuditEntry(ctx context.Context, req *connect.Request[auditv1.GetAuditEntryRequest]) (*connect.Response[auditv1.GetAuditEntryResponse], error) {
	entry, err := as.deps.Read.GetEntry(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &auditv1.GetAuditEntryResponse{}
	resp.SetData(entryToProto(entry))
	return connect.NewResponse(resp), nil
}

// ListAuditEntries streams pages of entries until count is met.
func (as *AuditServer) ListAuditEntries(ctx context.Context, req *connect.Request[auditv1.ListAuditEntriesRequest], stream *connect.ServerStream[auditv1.ListAuditEntriesResponse]) error {
	filter := &repository.AuditFilter{
		ProfileID: req.Msg.GetProfileId(), Action: req.Msg.GetAction(), ResourceType: req.Msg.GetResourceType(),
		ResourceID: req.Msg.GetResourceId(), Service: req.Msg.GetService(), TargetProfileID: req.Msg.GetTargetProfileId(),
		DeviceID: req.Msg.GetDeviceId(), IntentID: req.Msg.GetIntentId(), EventID: req.Msg.GetEventId(),
		CorrelationID: req.Msg.GetCorrelationId(), OnBehalfOf: req.Msg.GetOnBehalfOf(),
		SeqFrom: req.Msg.GetSeqFrom(), SeqTo: req.Msg.GetSeqTo(),
		Limit: int(req.Msg.GetCount()), Cursor: req.Msg.GetPage(),
	}
	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		filter.StartDate = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
		filter.EndDate = &t
	}
	entries, err := as.deps.Read.ListEntries(ctx, filter)
	if err != nil {
		return toConnectError(err)
	}
	return sendEntryPages(entries, func(page []*auditv1.AuditEntryObject) error {
		resp := &auditv1.ListAuditEntriesResponse{}
		resp.SetData(page)
		return stream.Send(resp)
	})
}

// SearchAuditEntries performs a bounded prefix search.
func (as *AuditServer) SearchAuditEntries(ctx context.Context, req *connect.Request[auditv1.SearchAuditEntriesRequest], stream *connect.ServerStream[auditv1.SearchAuditEntriesResponse]) error {
	var start, end *time.Time
	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		start = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
		end = &t
	}
	entries, err := as.deps.Read.SearchEntries(ctx, req.Msg.GetQuery(), start, end, int(req.Msg.GetCount()), req.Msg.GetPage())
	if err != nil {
		return toConnectError(err)
	}
	return sendEntryPages(entries, func(page []*auditv1.AuditEntryObject) error {
		resp := &auditv1.SearchAuditEntriesResponse{}
		resp.SetData(page)
		return stream.Send(resp)
	})
}

// VerifyIntegrity verifies a sequence range from the nearest checkpoint.
func (as *AuditServer) VerifyIntegrity(ctx context.Context, req *connect.Request[auditv1.VerifyIntegrityRequest]) (*connect.Response[auditv1.VerifyIntegrityResponse], error) {
	caller := business.CallerFromClaims(ctx)
	var start, end *time.Time
	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		start = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
		end = &t
	}
	startSeq, endSeq, err := as.deps.Verify.ResolveRange(ctx, caller.TenantID, req.Msg.GetStartSeq(), req.Msg.GetEndSeq(), start, end)
	if err != nil {
		return nil, toConnectError(err)
	}
	res, err := as.deps.Verify.VerifyIntegrity(ctx, caller.TenantID, startSeq, endSeq)
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &auditv1.VerifyIntegrityResponse{}
	resp.SetValid(res.Valid)
	resp.SetEntriesVerified(res.EntriesVerified)
	resp.SetFirstInvalidEntryId(res.FirstInvalidEntry)
	resp.SetFirstInvalidSeq(res.FirstInvalidSeq)
	resp.SetMessage(res.Message)
	resp.SetStartCheckpointSeq(res.StartCheckpointSeq)
	resp.SetEndSeq(res.EndSeq)
	resp.SetEndHash(res.EndHash)
	resp.SetKeyIdsUsed(res.KeyIDsUsed)
	resp.SetPartial(res.Partial)
	return connect.NewResponse(resp), nil
}

// ExportAuditEntries streams a verifiable bundle.
func (as *AuditServer) ExportAuditEntries(ctx context.Context, req *connect.Request[auditv1.ExportAuditEntriesRequest], stream *connect.ServerStream[auditv1.ExportAuditEntriesResponse]) error {
	caller := business.CallerFromClaims(ctx)
	startSeq, endSeq, err := as.deps.Verify.ResolveRange(ctx, caller.TenantID, req.Msg.GetStartSeq(), req.Msg.GetEndSeq(), nil, nil)
	if err != nil {
		return toConnectError(err)
	}
	sink := &exportStream{stream: stream}
	if err = as.deps.Verify.Export(ctx, caller.TenantID, startSeq, endSeq, sink); err != nil {
		return toConnectError(err)
	}
	return sink.flush()
}

// ListCheckpoints lists signed checkpoints for the caller's tenant.
func (as *AuditServer) ListCheckpoints(ctx context.Context, req *connect.Request[auditv1.ListCheckpointsRequest]) (*connect.Response[auditv1.ListCheckpointsResponse], error) {
	caller := business.CallerFromClaims(ctx)
	cps, err := as.deps.Read.ListCheckpoints(ctx, caller.TenantID, req.Msg.GetSeqFrom(), req.Msg.GetSeqTo(), int(req.Msg.GetCount()))
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*auditv1.AuditCheckpoint, 0, len(cps))
	for _, c := range cps {
		out = append(out, checkpointToProto(c))
	}
	resp := &auditv1.ListCheckpointsResponse{}
	resp.SetData(out)
	return connect.NewResponse(resp), nil
}

// GetSigningKeys returns all public keys.
func (as *AuditServer) GetSigningKeys(ctx context.Context, _ *connect.Request[auditv1.GetSigningKeysRequest]) (*connect.Response[auditv1.GetSigningKeysResponse], error) {
	keys, err := as.deps.Keys.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*auditv1.SigningKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, signingKeyToProto(k))
	}
	resp := &auditv1.GetSigningKeysResponse{}
	resp.SetData(out)
	return connect.NewResponse(resp), nil
}

// RegisterAuditManifest registers the calling service's vocabulary.
func (as *AuditServer) RegisterAuditManifest(ctx context.Context, req *connect.Request[auditv1.RegisterAuditManifestRequest]) (*connect.Response[auditv1.RegisterAuditManifestResponse], error) {
	res, err := as.deps.Manifests.Register(ctx, as.caller(ctx), req.Msg.GetManifest())
	if err != nil {
		return nil, toConnectError(err)
	}
	resp := &auditv1.RegisterAuditManifestResponse{}
	resp.SetService(res.Service)
	resp.SetVersion(res.Version)
	resp.SetUnchanged(res.Unchanged)
	return connect.NewResponse(resp), nil
}

// GetAuditManifest returns the latest manifest for a service.
func (as *AuditServer) GetAuditManifest(ctx context.Context, req *connect.Request[auditv1.GetAuditManifestRequest]) (*connect.Response[auditv1.GetAuditManifestResponse], error) {
	row, err := as.deps.Manifests.Get(ctx, req.Msg.GetService())
	if err != nil {
		return nil, toConnectError(err)
	}
	if row == nil {
		return nil, connect.NewError(connect.CodeNotFound, business.ErrKeyNotFound)
	}
	resp := &auditv1.GetAuditManifestResponse{}
	resp.SetManifest(business.ManifestToProto(row))
	resp.SetVersion(row.ManifestVer)
	resp.SetCreatedAt(timestamppb.New(row.CreatedAt))
	return connect.NewResponse(resp), nil
}

// RequeueIntake returns FAILED rows to ACCEPTED and audits the operation.
func (as *AuditServer) RequeueIntake(ctx context.Context, req *connect.Request[auditv1.RequeueIntakeRequest]) (*connect.Response[auditv1.RequeueIntakeResponse], error) {
	n, err := as.deps.Ingest.Requeue(ctx, req.Msg.GetIntakeIds())
	if err != nil {
		return nil, toConnectError(err)
	}
	as.selfAudit(ctx, "requeue_intake", "audit_intake", "", map[string]any{"requeued": float64(n)})
	resp := &auditv1.RequeueIntakeResponse{}
	resp.SetRequeued(n)
	return connect.NewResponse(resp), nil
}

// RetireSigningKey retires a key and audits the operation.
func (as *AuditServer) RetireSigningKey(ctx context.Context, req *connect.Request[auditv1.RetireSigningKeyRequest]) (*connect.Response[auditv1.RetireSigningKeyResponse], error) {
	key, err := as.deps.Keys.Retire(ctx, req.Msg.GetKeyId())
	if err != nil {
		return nil, toConnectError(err)
	}
	as.selfAudit(ctx, "retire_signing_key", "audit_signing_key", key.KeyID, nil)
	resp := &auditv1.RetireSigningKeyResponse{}
	resp.SetKey(signingKeyToProto(key))
	return connect.NewResponse(resp), nil
}

// selfAudit records an operator action under the audit service's own name.
// It is best-effort: a failure is logged by the ingest layer's rejection
// path and must not fail the operator call.
func (as *AuditServer) selfAudit(ctx context.Context, action, resourceType, resourceID string, details map[string]any) {
	caller := business.CallerFromClaims(ctx)
	caller.CanCreateAny = true
	req := &auditv1.CreateAuditEntryRequest{}
	req.SetProfileId(caller.ProfileID)
	req.SetAction(action)
	req.SetResourceType(resourceType)
	req.SetResourceId(resourceID)
	req.SetService(selfAuditService)
	if details != nil {
		if s, err := structpb.NewStruct(details); err == nil {
			req.SetDetails(s)
		}
	}
	_, _ = as.deps.Ingest.Create(ctx, caller, req)
}

const selfAuditService = "service_audit"

// ---------------------------------------------------------------------------
// conversions
// ---------------------------------------------------------------------------

const listPageSize = 500

func sendEntryPages(entries []*models.AuditEntry, send func([]*auditv1.AuditEntryObject) error) error {
	for start := 0; start < len(entries); start += listPageSize {
		end := min(start+listPageSize, len(entries))
		page := make([]*auditv1.AuditEntryObject, 0, end-start)
		for _, e := range entries[start:end] {
			page = append(page, entryToProto(e))
		}
		if err := send(page); err != nil {
			return err
		}
	}
	if len(entries) == 0 {
		return send([]*auditv1.AuditEntryObject{})
	}
	return nil
}

func receiptToProto(r *business.IntakeReceipt) *auditv1.CreateAuditEntryResponse {
	resp := &auditv1.CreateAuditEntryResponse{}
	resp.SetIntakeId(r.IntakeID)
	resp.SetEntryId(r.EntryID)
	resp.SetState(intakeStateToProto(r.State))
	return resp
}

func intakeStateToProto(s string) auditv1.IntakeState {
	switch s {
	case models.IntakeStateAccepted:
		return auditv1.IntakeState_INTAKE_STATE_ACCEPTED
	case models.IntakeStateCommitted:
		return auditv1.IntakeState_INTAKE_STATE_COMMITTED
	case models.IntakeStateFailed:
		return auditv1.IntakeState_INTAKE_STATE_FAILED
	default:
		return auditv1.IntakeState_INTAKE_STATE_UNSPECIFIED
	}
}

func entryToProto(e *models.AuditEntry) *auditv1.AuditEntryObject {
	obj := &auditv1.AuditEntryObject{}
	obj.SetId(e.GetID())
	obj.SetTenantId(e.TenantID)
	obj.SetPartitionId(e.PartitionID)
	obj.SetProfileId(e.ProfileID)
	obj.SetAction(e.Action)
	obj.SetResourceType(e.ResourceType)
	obj.SetResourceId(e.ResourceID)
	obj.SetService(e.Service)
	if e.Details != nil {
		if details, err := structpb.NewStruct(structCompatible(e.Details)); err == nil {
			obj.SetDetails(details)
		}
	}
	obj.SetIpAddress(e.IPAddress)
	obj.SetUserAgent(e.UserAgent)
	obj.SetDeviceId(e.DeviceID)
	obj.SetTargetProfileId(e.TargetProfileID)
	obj.SetTraceId(e.TraceID)
	if !e.CreatedAt.IsZero() {
		obj.SetCreatedAt(timestamppb.New(e.CreatedAt))
	}
	obj.SetPreviousHash(e.PreviousHash)
	obj.SetEntryHash(e.EntryHash)
	obj.SetSignature(e.Signature)
	obj.SetSeq(e.Seq)
	obj.SetKeyId(e.KeyID)
	obj.SetCanonVersion(int32(e.CanonVersion))
	obj.SetEntryId(e.EntryID)
	obj.SetActorServiceAccountId(e.ActorServiceAccountID)
	obj.SetOnBehalfOf(e.OnBehalfOf)
	if !e.OccurredAt.IsZero() {
		obj.SetOccurredAt(timestamppb.New(e.OccurredAt))
	}
	if !e.ReceivedAt.IsZero() {
		obj.SetReceivedAt(timestamppb.New(e.ReceivedAt))
	}
	obj.SetCorrelationId(e.CorrelationID)
	obj.SetEventId(e.EventID)
	obj.SetIntentId(e.IntentID)
	obj.SetInstanceId(e.InstanceID)
	obj.SetPayloadHash(e.PayloadHash)
	obj.SetAuthorizationHash(e.AuthorizationHash)
	obj.SetPolicyHash(e.PolicyHash)
	obj.SetDeviceKeyId(e.DeviceKeyID)
	obj.SetStateFrom(e.StateFrom)
	obj.SetStateTo(e.StateTo)
	obj.SetResourceVersion(e.ResourceVersion)
	obj.SetRelations(relationsToProto(e.Relations))
	obj.SetManifestVersion(e.ManifestVersion)
	obj.SetUnmanifested(e.Unmanifested)
	obj.SetState(auditv1.IntakeState_INTAKE_STATE_COMMITTED)
	return obj
}

// structCompatible converts database-decoded JSON (json.Number values) into
// the float64/map/slice shapes structpb.NewStruct accepts.
func structCompatible(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = structValue(v)
	}
	return out
}

func structValue(v any) any {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return x.String()
		}
		return f
	case map[string]any:
		return structCompatible(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = structValue(item)
		}
		return out
	default:
		return v
	}
}

func relationsToProto(rels map[string]any) []*auditv1.AuditRelation {
	if rels == nil {
		return nil
	}
	items, _ := rels["items"].([]any)
	out := make([]*auditv1.AuditRelation, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		r := &auditv1.AuditRelation{}
		str := func(k string) string { s, _ := m[k].(string); return s }
		r.SetParentType(str("parent_type"))
		r.SetParentId(str("parent_id"))
		r.SetChildType(str("child_type"))
		r.SetChildId(str("child_id"))
		r.SetAction(str("action"))
		out = append(out, r)
	}
	return out
}

func checkpointToProto(c *models.AuditCheckpoint) *auditv1.AuditCheckpoint {
	out := &auditv1.AuditCheckpoint{}
	out.SetTenantId(c.TenantID)
	out.SetSeq(c.Seq)
	out.SetEntryHash(c.EntryHash)
	out.SetKeyId(c.KeyID)
	out.SetSignature(c.Signature)
	out.SetCreatedAt(timestamppb.New(c.CreatedAt))
	return out
}

func signingKeyToProto(k *models.AuditSigningKey) *auditv1.SigningKey {
	out := &auditv1.SigningKey{}
	out.SetKeyId(k.KeyID)
	out.SetAlgorithm(k.Algorithm)
	out.SetPublicKey(hex.EncodeToString(k.PublicKey))
	out.SetValidFrom(timestamppb.New(k.ValidFrom))
	if k.RetiredAt != nil {
		out.SetRetiredAt(timestamppb.New(*k.RetiredAt))
	}
	return out
}

// exportStream adapts the Connect server stream to business.ExportSink.
type exportStream struct {
	stream *connect.ServerStream[auditv1.ExportAuditEntriesResponse]
}

func (s *exportStream) Header(h *business.ExportHeader) error {
	hdr := &auditv1.ExportAuditEntriesResponse_Header{}
	hdr.SetTenantId(h.TenantID)
	hdr.SetStartSeq(h.StartSeq)
	hdr.SetEndSeq(h.EndSeq)
	if h.StartCheckpoint != nil {
		hdr.SetStartCheckpoint(checkpointToProto(h.StartCheckpoint))
	}
	if h.EndCheckpoint != nil {
		hdr.SetEndCheckpoint(checkpointToProto(h.EndCheckpoint))
	}
	keys := make([]*auditv1.SigningKey, 0, len(h.Keys))
	for _, k := range h.Keys {
		keys = append(keys, signingKeyToProto(k))
	}
	hdr.SetKeys(keys)
	msg := &auditv1.ExportAuditEntriesResponse{}
	msg.SetHeader(hdr)
	return s.stream.Send(msg)
}

func (s *exportStream) Entry(e *models.AuditEntry) error {
	msg := &auditv1.ExportAuditEntriesResponse{}
	msg.SetEntry(entryToProto(e))
	return s.stream.Send(msg)
}

func (s *exportStream) flush() error { return nil }
