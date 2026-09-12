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
	"errors"
	"fmt"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrHeadConflict is returned when the compare-and-swap on the head row
// affects zero rows. It cannot happen while the advisory lock is held and
// exists as a guard against a lock-free code path being introduced later.
var ErrHeadConflict = errors.New("audit chain head changed underneath the writer")

// entryInsertChunk keeps multi-row inserts under the Postgres parameter
// limit for AuditEntry's column count.
const entryInsertChunk = 100

type chainRepository struct {
	pool pool.Pool
}

// NewChainRepository creates the writer-side chain repository.
func NewChainRepository(dbPool pool.Pool) ChainRepository {
	return &chainRepository{pool: dbPool}
}

func (r *chainRepository) DiscoverBacklog(ctx context.Context, limit int) ([]TenantBacklog, error) {
	var out []TenantBacklog
	err := r.pool.DB(ctx, false).Raw(
		`SELECT tenant_id, COUNT(*) AS count, MIN(received_at) AS oldest
		 FROM audit_intake WHERE state = ?
		 GROUP BY tenant_id ORDER BY MIN(received_at) ASC LIMIT ?`,
		models.IntakeStateAccepted, limit).Scan(&out).Error
	return out, err
}

func (r *chainRepository) CommitBatch(ctx context.Context, tenantID string, fn func(tx ChainTx) error) error {
	return r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		// Transaction-scoped lock: released on commit or rollback, safe behind
		// a transaction-mode pooler. Session-level locks are not.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", tenantID).Error; err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}

		head := &models.AuditChainHead{}
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", tenantID).First(head).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			now := time.Now().UTC()
			head = &models.AuditChainHead{}
			head.ID = tenantID
			head.TenantID = tenantID
			head.CreatedAt, head.ModifiedAt, head.Version = now, now, 1
			if err = tx.Create(head).Error; err != nil {
				return fmt.Errorf("create genesis head: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("lock head: %w", err)
		}

		return fn(&chainTx{db: tx, tenantID: tenantID, head: head})
	})
}

type chainTx struct {
	db       *gorm.DB
	tenantID string
	head     *models.AuditChainHead
}

func (t *chainTx) Head() *models.AuditChainHead { return t.head }

func (t *chainTx) ClaimIntake(limit int) ([]*models.AuditIntake, error) {
	var rows []*models.AuditIntake
	err := t.db.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
		Where("tenant_id = ? AND state = ?", t.tenantID, models.IntakeStateAccepted).
		Order("received_at ASC, id ASC").Limit(limit).Find(&rows).Error
	return rows, err
}

func (t *chainTx) InsertEntries(entries []*models.AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	return t.db.CreateInBatches(entries, entryInsertChunk).Error
}

func (t *chainTx) InsertCheckpoint(c *models.AuditCheckpoint) error {
	return t.db.Create(c).Error
}

func (t *chainTx) MarkCommitted(ids []string, seqs []int64) error {
	if len(ids) != len(seqs) {
		return errors.New("mark committed: ids and seqs length mismatch")
	}
	now := time.Now().UTC()
	for i, id := range ids {
		res := t.db.Table(models.AuditIntake{}.TableName()).Where("id = ?", id).
			Updates(map[string]any{"state": models.IntakeStateCommitted, "committed_seq": seqs[i], "modified_at": now})
		if res.Error != nil {
			return res.Error
		}
	}
	return nil
}

func (t *chainTx) MarkFailed(id, reason string) error {
	return t.db.Table(models.AuditIntake{}.TableName()).Where("id = ?", id).
		Updates(map[string]any{
			"state": models.IntakeStateFailed, "last_error": reason,
			"attempts": gorm.Expr("attempts + 1"), "modified_at": time.Now().UTC(),
		}).Error
}

func (t *chainTx) AdvanceHead(newSeq int64, entryHash string) error {
	res := t.db.Table(models.AuditChainHead{}.TableName()).
		Where("id = ? AND seq = ?", t.tenantID, t.head.Seq).
		Updates(map[string]any{"seq": newSeq, "entry_hash": entryHash, "modified_at": time.Now().UTC()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return ErrHeadConflict
	}
	t.head.Seq, t.head.EntryHash = newSeq, entryHash
	return nil
}
