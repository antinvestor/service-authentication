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

package business

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
	"gorm.io/gorm"
)

// ErrBacklogExceeded is returned when a tenant's intake exceeds the cap.
var ErrBacklogExceeded = errors.New("audit intake backlog exceeded for tenant; retry later")

// IntakeReceipt is what the RPC returns on acceptance.
type IntakeReceipt struct {
	IntakeID string
	EntryID  string
	State    string
}

// IngestBusiness validates and durably accepts entries.
type IngestBusiness interface {
	Create(ctx context.Context, caller Caller, req *auditv1.CreateAuditEntryRequest) (*IntakeReceipt, error)
	CreateBatch(ctx context.Context, caller Caller, reqs []*auditv1.CreateAuditEntryRequest) ([]*IntakeReceipt, error)
	// Requeue moves FAILED intake rows back to ACCEPTED.
	Requeue(ctx context.Context, ids []string) (int64, error)
}

type ingestBusiness struct {
	cfg        *aconfig.AuditConfig
	validator  *Validator
	intake     repository.IntakeRepository
	rejections repository.RejectionRepository
	metrics    *Metrics
	now        func() time.Time
}

// NewIngestBusiness wires the validator to the intake table.
func NewIngestBusiness(cfg *aconfig.AuditConfig, validator *Validator, intake repository.IntakeRepository,
	rejections repository.RejectionRepository, metrics *Metrics) IngestBusiness {
	return &ingestBusiness{cfg: cfg, validator: validator, intake: intake, rejections: rejections, metrics: metrics, now: func() time.Time { return time.Now().UTC() }}
}

func (ib *ingestBusiness) Create(ctx context.Context, caller Caller, req *auditv1.CreateAuditEntryRequest) (*IntakeReceipt, error) {
	receipts, err := ib.CreateBatch(ctx, caller, []*auditv1.CreateAuditEntryRequest{req})
	if err != nil {
		return nil, err
	}
	return receipts[0], nil
}

func (ib *ingestBusiness) CreateBatch(ctx context.Context, caller Caller, reqs []*auditv1.CreateAuditEntryRequest) ([]*IntakeReceipt, error) {
	ctx, span := tracer().Start(ctx, "audit.ingest")
	defer span.End()

	if len(reqs) == 0 || len(reqs) > MaxBatch {
		return nil, &ValidationError{Reason: ReasonSize, Field: "entries", Detail: fmt.Sprintf("batch must hold 1..%d entries", MaxBatch)}
	}

	if ib.cfg.IntakeMaxBacklog > 0 {
		backlog, err := ib.intake.Backlog(ctx, caller.TenantID)
		if err != nil {
			return nil, fmt.Errorf("intake backlog: %w", err)
		}
		if backlog >= int64(ib.cfg.IntakeMaxBacklog) {
			return nil, ErrBacklogExceeded
		}
	}

	now := ib.now()
	// Validate every entry before touching the database so a batch is
	// accepted or rejected as a whole.
	normalised := make([]*models.AuditEntry, 0, len(reqs))
	for i, req := range reqs {
		n, verr := ib.validator.Validate(ctx, caller, req, now)
		if verr != nil {
			ib.recordRejection(ctx, caller, req, verr)
			verr.Field = fmt.Sprintf("entries[%d].%s", i, verr.Field)
			if len(reqs) == 1 {
				verr.Field = verr.Field[len("entries[0]."):]
			}
			return nil, verr
		}
		// Within a batch, received_at increases monotonically so the writer
		// commits the batch contiguously in request order.
		n.Entry.ReceivedAt = now.Add(time.Duration(i) * time.Microsecond)
		normalised = append(normalised, n.Entry)
	}

	receipts := make([]*IntakeReceipt, 0, len(normalised))
	for _, e := range normalised {
		receipt, err := ib.accept(ctx, e)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func (ib *ingestBusiness) accept(ctx context.Context, e *models.AuditEntry) (*IntakeReceipt, error) {
	row := &models.AuditIntake{
		Service: e.Service, EntryID: e.EntryID, Payload: EntryToPayload(e),
		ReceivedAt: e.ReceivedAt, State: models.IntakeStateAccepted,
	}
	row.TenantID, row.PartitionID, row.AccessID = e.TenantID, e.PartitionID, e.AccessID
	row.GenID(ctx)

	err := ib.intake.Create(ctx, row)
	if err == nil {
		ib.metrics.IntakeAccepted.Add(ctx, 1, attrService.String(e.Service))
		return &IntakeReceipt{IntakeID: row.ID, EntryID: e.EntryID, State: models.IntakeStateAccepted}, nil
	}
	if !isUniqueViolation(err) {
		return nil, fmt.Errorf("persist intake: %w", err)
	}
	// Idempotent retry: return the existing row as it stands.
	existing, gerr := ib.intake.GetByDedupe(ctx, e.TenantID, e.Service, e.EntryID)
	if gerr != nil {
		return nil, fmt.Errorf("resolve duplicate intake: %w", gerr)
	}
	return &IntakeReceipt{IntakeID: existing.ID, EntryID: existing.EntryID, State: existing.State}, nil
}

func (ib *ingestBusiness) recordRejection(ctx context.Context, caller Caller, req *auditv1.CreateAuditEntryRequest, verr *ValidationError) {
	ib.metrics.IntakeRejected.Add(ctx, 1, attrService.String(req.GetService()), attrReason.String(verr.Reason))
	row := &models.AuditRejection{
		Service: req.GetService(), Reason: verr.Reason, Field: verr.Field, EntryID: req.GetEntryId(), ReceivedAt: ib.now(),
	}
	row.TenantID, row.PartitionID, row.AccessID = caller.TenantID, caller.PartitionID, caller.AccessID
	if err := ib.rejections.Create(ctx, row); err != nil {
		util.Log(ctx).WithError(err).Warn("audit: could not record rejection")
	}
}

func (ib *ingestBusiness) Requeue(ctx context.Context, ids []string) (int64, error) {
	return ib.intake.Requeue(ctx, ids)
}

func isUniqueViolation(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	return err != nil && (contains(err.Error(), "SQLSTATE 23505") || contains(err.Error(), "duplicate key"))
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// EntryToPayload serialises the validated entry for the intake row. Only
// producer-supplied and caller-derived fields are stored; chain fields are
// assigned by the writer.
func EntryToPayload(e *models.AuditEntry) data.JSONMap {
	p := data.JSONMap{
		"profile_id": e.ProfileID, "action": e.Action, "resource_type": e.ResourceType, "resource_id": e.ResourceID,
		"service": e.Service, "ip_address": e.IPAddress, "user_agent": e.UserAgent, "device_id": e.DeviceID,
		"target_profile_id": e.TargetProfileID, "trace_id": e.TraceID, "entry_id": e.EntryID,
		"actor_service_account_id": e.ActorServiceAccountID, "on_behalf_of": e.OnBehalfOf,
		"occurred_at": e.OccurredAt.UTC().Format(time.RFC3339Nano), "received_at": e.ReceivedAt.UTC().Format(time.RFC3339Nano),
		"manifest_version": float64(e.ManifestVersion), "unmanifested": e.Unmanifested,
		"correlation_id": e.CorrelationID, "event_id": e.EventID, "intent_id": e.IntentID, "instance_id": e.InstanceID,
		"payload_hash": e.PayloadHash, "authorization_hash": e.AuthorizationHash, "policy_hash": e.PolicyHash,
		"device_key_id": e.DeviceKeyID, "state_from": e.StateFrom, "state_to": e.StateTo,
		"resource_version": float64(e.ResourceVersion),
		"tenant_id":        e.TenantID, "partition_id": e.PartitionID, "access_id": e.AccessID,
	}
	if e.Details != nil {
		p["details"] = map[string]any(e.Details)
	}
	if e.Relations != nil {
		p["relations"] = map[string]any(e.Relations)
	}
	return p
}

// EntryFromPayload rebuilds an entry from an intake row.
func EntryFromPayload(row *models.AuditIntake) (*models.AuditEntry, error) {
	p := row.Payload
	str := func(k string) string { s, _ := p[k].(string); return s }
	num := func(k string) int64 {
		switch v := p[k].(type) {
		case float64:
			return int64(v)
		case json.Number:
			n, _ := v.Int64()
			return n
		case int64:
			return v
		default:
			return 0
		}
	}
	ts := func(k string) (time.Time, error) {
		s := str(k)
		if s == "" {
			return time.Time{}, nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		return t.Truncate(time.Microsecond), err
	}
	occurredAt, err := ts("occurred_at")
	if err != nil {
		return nil, fmt.Errorf("payload occurred_at: %w", err)
	}
	receivedAt, err := ts("received_at")
	if err != nil {
		return nil, fmt.Errorf("payload received_at: %w", err)
	}
	e := &models.AuditEntry{
		ProfileID: str("profile_id"), Action: str("action"), ResourceType: str("resource_type"), ResourceID: str("resource_id"),
		Service: str("service"), IPAddress: str("ip_address"), UserAgent: str("user_agent"), DeviceID: str("device_id"),
		TargetProfileID: str("target_profile_id"), TraceID: str("trace_id"), EntryID: str("entry_id"),
		ActorServiceAccountID: str("actor_service_account_id"), OnBehalfOf: str("on_behalf_of"),
		OccurredAt: occurredAt.UTC(), ReceivedAt: receivedAt.UTC(), ManifestVersion: int32(num("manifest_version")),
		CorrelationID: str("correlation_id"), EventID: str("event_id"), IntentID: str("intent_id"), InstanceID: str("instance_id"),
		PayloadHash: str("payload_hash"), AuthorizationHash: str("authorization_hash"), PolicyHash: str("policy_hash"),
		DeviceKeyID: str("device_key_id"), StateFrom: str("state_from"), StateTo: str("state_to"),
		ResourceVersion: num("resource_version"), CanonVersion: models.CanonVersionV2,
	}
	e.Unmanifested, _ = p["unmanifested"].(bool)
	e.TenantID, e.PartitionID, e.AccessID = row.TenantID, row.PartitionID, row.AccessID
	if d, ok := p["details"].(map[string]any); ok {
		e.Details = data.JSONMap(d)
	}
	if r, ok := p["relations"].(map[string]any); ok {
		e.Relations = data.JSONMap(r)
	}
	if e.Action == "" || e.ProfileID == "" || e.Service == "" {
		return nil, errors.New("payload is missing required fields")
	}
	return e, nil
}
