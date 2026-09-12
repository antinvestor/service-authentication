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

package repository

import (
	"context"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
)

// AuditEntryRepository is the append-only data access interface for audit
// entries. By design, no Update or Delete methods are exposed; inserts
// happen only inside ChainRepository.CommitBatch.
type AuditEntryRepository interface {
	GetByID(ctx context.Context, id string) (*models.AuditEntry, error)
	GetBySeq(ctx context.Context, tenantID string, seq int64) (*models.AuditEntry, error)
	List(ctx context.Context, filter *AuditFilter) ([]*models.AuditEntry, error)
	Search(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error)
	// ListChainBySeq returns entries with seq in [fromSeq, toSeq] ascending,
	// at most limit rows (keyset on seq, never OFFSET).
	ListChainBySeq(ctx context.Context, tenantID string, fromSeq, toSeq int64, limit int) ([]*models.AuditEntry, error)
	// SeqAtOrAfter resolves a time to the first seq whose created_at >= t (0 if none).
	SeqAtOrAfter(ctx context.Context, tenantID string, t time.Time) (int64, error)
	// SeqAtOrBefore resolves a time to the last seq whose created_at <= t (0 if none).
	SeqAtOrBefore(ctx context.Context, tenantID string, t time.Time) (int64, error)
}

// AuditFilter specifies query parameters for listing audit entries.
type AuditFilter struct {
	ProfileID       string
	Action          string
	ResourceType    string
	ResourceID      string
	Service         string
	TargetProfileID string
	DeviceID        string
	IntentID        string
	EventID         string
	CorrelationID   string
	OnBehalfOf      string
	SeqFrom         int64
	SeqTo           int64
	StartDate       *time.Time
	EndDate         *time.Time
	Limit           int
	Cursor          string // ID of the last entry from the previous page
}

// BySeq reports whether the filter orders by sequence.
func (f *AuditFilter) BySeq() bool { return f.SeqFrom > 0 || f.SeqTo > 0 }

// IntakeRepository stores accepted entries until the writer commits them.
type IntakeRepository interface {
	Create(ctx context.Context, row *models.AuditIntake) error
	GetByID(ctx context.Context, id string) (*models.AuditIntake, error)
	// GetByDedupe returns the row for (tenantID, service, entryID) or a not-found error.
	GetByDedupe(ctx context.Context, tenantID, service, entryID string) (*models.AuditIntake, error)
	// Backlog counts ACCEPTED rows for the tenant in ctx.
	Backlog(ctx context.Context, tenantID string) (int64, error)
	// OldestAccepted returns the received_at of the oldest ACCEPTED row across
	// all tenants visible to ctx (zero time when none).
	OldestAccepted(ctx context.Context) (time.Time, error)
	// Requeue moves FAILED rows back to ACCEPTED; returns the count changed.
	Requeue(ctx context.Context, ids []string) (int64, error)
	// CountFailed counts FAILED rows visible to ctx.
	CountFailed(ctx context.Context) (int64, error)
	// DeleteCommittedBefore removes up to limit COMMITTED rows older than t.
	DeleteCommittedBefore(ctx context.Context, t time.Time, limit int) (int64, error)
}

// RejectionRepository records validator refusals without content.
type RejectionRepository interface {
	Create(ctx context.Context, row *models.AuditRejection) error
	CountByService(ctx context.Context, service string, since time.Time) (int64, error)
	DeleteBefore(ctx context.Context, t time.Time, limit int) (int64, error)
}

// CheckpointRepository reads signed checkpoints; inserts happen in CommitBatch.
type CheckpointRepository interface {
	// LatestAtOrBefore returns the checkpoint with the greatest seq <= seq, or nil.
	LatestAtOrBefore(ctx context.Context, tenantID string, seq int64) (*models.AuditCheckpoint, error)
	// FirstAtOrAfter returns the checkpoint with the smallest seq >= seq, or nil.
	FirstAtOrAfter(ctx context.Context, tenantID string, seq int64) (*models.AuditCheckpoint, error)
	// Latest returns the newest checkpoint for the tenant, or nil.
	Latest(ctx context.Context, tenantID string) (*models.AuditCheckpoint, error)
	List(ctx context.Context, tenantID string, fromSeq, toSeq int64, limit int) ([]*models.AuditCheckpoint, error)
}

// SigningKeyRepository is the global registry of public keys.
type SigningKeyRepository interface {
	Create(ctx context.Context, key *models.AuditSigningKey) error
	GetByKeyID(ctx context.Context, keyID string) (*models.AuditSigningKey, error)
	List(ctx context.Context) ([]*models.AuditSigningKey, error)
	Retire(ctx context.Context, keyID string, at time.Time) error
}

// ManifestRepository stores versioned vocabularies per service.
type ManifestRepository interface {
	Create(ctx context.Context, m *models.AuditManifest) error
	Latest(ctx context.Context, service string) (*models.AuditManifest, error)
}

// ChainHeadRepository reads chain tips outside the writer transaction.
type ChainHeadRepository interface {
	Get(ctx context.Context, tenantID string) (*models.AuditChainHead, error)
}

// TenantBacklog is one tenant's pending intake.
type TenantBacklog struct {
	TenantID string
	Count    int64
	Oldest   time.Time
}

// ChainTx is the unit of work the writer runs under the per-tenant lock.
type ChainTx interface {
	Head() *models.AuditChainHead
	ClaimIntake(limit int) ([]*models.AuditIntake, error)
	InsertEntries(entries []*models.AuditEntry) error
	InsertCheckpoint(c *models.AuditCheckpoint) error
	MarkCommitted(ids []string, seqs []int64) error
	MarkFailed(id, reason string) error
	// AdvanceHead compare-and-swaps the head from Head().Seq to newSeq.
	AdvanceHead(newSeq int64, entryHash string) error
}

// ChainRepository owns the serialised chain-append transaction.
type ChainRepository interface {
	// DiscoverBacklog lists tenants with ACCEPTED intake, oldest first. The
	// caller must supply a context elevated to see all tenants.
	DiscoverBacklog(ctx context.Context, limit int) ([]TenantBacklog, error)
	// CommitBatch runs fn inside one transaction on the primary holding
	// pg_advisory_xact_lock(hashtext(tenantID)) and the head row FOR UPDATE.
	// The genesis head is created when absent. Any error rolls back.
	CommitBatch(ctx context.Context, tenantID string, fn func(tx ChainTx) error) error
}
