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
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"gorm.io/gorm"
)

type intakeRepository struct {
	datastore.BaseRepository[*models.AuditIntake]
}

// NewIntakeRepository creates the intake repository.
func NewIntakeRepository(ctx context.Context, dbPool pool.Pool) IntakeRepository {
	return &intakeRepository{
		BaseRepository: datastore.NewBaseRepository[*models.AuditIntake](ctx, dbPool, nil,
			func() *models.AuditIntake { return &models.AuditIntake{} }),
	}
}

func (r *intakeRepository) GetByDedupe(ctx context.Context, tenantID, service, entryID string) (*models.AuditIntake, error) {
	row := &models.AuditIntake{}
	err := r.Pool().DB(ctx, false).Where("tenant_id = ? AND service = ? AND entry_id = ?", tenantID, service, entryID).First(row).Error
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (r *intakeRepository) Backlog(ctx context.Context, tenantID string) (int64, error) {
	var n int64
	err := r.Pool().DB(ctx, false).Model(&models.AuditIntake{}).
		Where("tenant_id = ? AND state = ?", tenantID, models.IntakeStateAccepted).Count(&n).Error
	return n, err
}

func (r *intakeRepository) OldestAccepted(ctx context.Context) (time.Time, error) {
	var row models.AuditIntake
	err := r.Pool().DB(ctx, false).Where("state = ?", models.IntakeStateAccepted).
		Order("received_at ASC").Limit(1).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return row.ReceivedAt, nil
}

func (r *intakeRepository) Requeue(ctx context.Context, ids []string) (int64, error) {
	res := r.Pool().DB(ctx, false).Table(models.AuditIntake{}.TableName()).
		Where("id IN ? AND state = ?", ids, models.IntakeStateFailed).
		Updates(map[string]any{"state": models.IntakeStateAccepted, "last_error": "", "modified_at": time.Now().UTC()})
	return res.RowsAffected, res.Error
}

func (r *intakeRepository) CountFailed(ctx context.Context) (int64, error) {
	var n int64
	err := r.Pool().DB(ctx, false).Model(&models.AuditIntake{}).
		Where("state = ?", models.IntakeStateFailed).Count(&n).Error
	return n, err
}

func (r *intakeRepository) DeleteCommittedBefore(ctx context.Context, t time.Time, limit int) (int64, error) {
	res := r.Pool().DB(ctx, false).Exec(
		`DELETE FROM audit_intake WHERE id IN (
			SELECT id FROM audit_intake WHERE state = ? AND received_at < ? ORDER BY received_at LIMIT ?)`,
		models.IntakeStateCommitted, t, limit)
	return res.RowsAffected, res.Error
}

// ---------------------------------------------------------------------------

type rejectionRepository struct {
	datastore.BaseRepository[*models.AuditRejection]
}

// NewRejectionRepository creates the rejection repository.
func NewRejectionRepository(ctx context.Context, dbPool pool.Pool) RejectionRepository {
	return &rejectionRepository{
		BaseRepository: datastore.NewBaseRepository[*models.AuditRejection](ctx, dbPool, nil,
			func() *models.AuditRejection { return &models.AuditRejection{} }),
	}
}

func (r *rejectionRepository) CountByService(ctx context.Context, service string, since time.Time) (int64, error) {
	var n int64
	err := r.Pool().DB(ctx, true).Model(&models.AuditRejection{}).
		Where("service = ? AND received_at >= ?", service, since).Count(&n).Error
	return n, err
}

func (r *rejectionRepository) DeleteBefore(ctx context.Context, t time.Time, limit int) (int64, error) {
	res := r.Pool().DB(ctx, false).Exec(
		`DELETE FROM audit_rejections WHERE id IN (
			SELECT id FROM audit_rejections WHERE received_at < ? ORDER BY received_at LIMIT ?)`, t, limit)
	return res.RowsAffected, res.Error
}

// ---------------------------------------------------------------------------

type checkpointRepository struct {
	pool pool.Pool
}

// NewCheckpointRepository creates the read-side checkpoint repository.
func NewCheckpointRepository(dbPool pool.Pool) CheckpointRepository {
	return &checkpointRepository{pool: dbPool}
}

func (r *checkpointRepository) one(db *gorm.DB) (*models.AuditCheckpoint, error) {
	c := &models.AuditCheckpoint{}
	if err := db.Take(c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return c, nil
}

func (r *checkpointRepository) LatestAtOrBefore(ctx context.Context, tenantID string, seq int64) (*models.AuditCheckpoint, error) {
	return r.one(r.pool.DB(tenantScope(ctx, tenantID), true).Where("tenant_id = ? AND seq <= ?", tenantID, seq).Order("seq DESC").Limit(1))
}

func (r *checkpointRepository) FirstAtOrAfter(ctx context.Context, tenantID string, seq int64) (*models.AuditCheckpoint, error) {
	return r.one(r.pool.DB(tenantScope(ctx, tenantID), true).Where("tenant_id = ? AND seq >= ?", tenantID, seq).Order("seq ASC").Limit(1))
}

func (r *checkpointRepository) Latest(ctx context.Context, tenantID string) (*models.AuditCheckpoint, error) {
	return r.one(r.pool.DB(tenantScope(ctx, tenantID), false).Where("tenant_id = ?", tenantID).Order("seq DESC").Limit(1))
}

func (r *checkpointRepository) List(ctx context.Context, tenantID string, fromSeq, toSeq int64, limit int) ([]*models.AuditCheckpoint, error) {
	db := r.pool.DB(tenantScope(ctx, tenantID), true).Where("tenant_id = ?", tenantID)
	if fromSeq > 0 {
		db = db.Where("seq >= ?", fromSeq)
	}
	if toSeq > 0 {
		db = db.Where("seq <= ?", toSeq)
	}
	var out []*models.AuditCheckpoint
	err := db.Order("seq ASC").Limit(normalizeLimit(limit)).Find(&out).Error
	return out, err
}
