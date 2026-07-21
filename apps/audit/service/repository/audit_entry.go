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
	"fmt"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"gorm.io/gorm"
)

const defaultLimit = 50
const maxLimit = 500

// createBatchSize is the GORM CreateInBatches chunk size. Large enough to
// amortise round-trips, small enough to stay under Postgres parameter limits
// (~65k) for AuditEntry's column count.
const createBatchSize = 100

type auditEntryRepository struct {
	pool pool.Pool
}

func NewAuditEntryRepository(dbPool pool.Pool) AuditEntryRepository {
	return &auditEntryRepository{pool: dbPool}
}

func (r *auditEntryRepository) Create(ctx context.Context, entry *models.AuditEntry) error {
	return r.pool.DB(ctx, false).Create(entry).Error
}

// CreateBatch persists entries with multi-row INSERT (CreateInBatches) inside
// a single transaction. Prefer this over N× Create for BatchCreateAuditEntries.
// Callers must pre-sign entries and pre-materialise BaseModel IDs/timestamps
// so hash chains stay consistent with stored rows.
func (r *auditEntryRepository) CreateBatch(ctx context.Context, entries []*models.AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	return r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		// CreateInBatches issues multi-value INSERTs (not N single-row Creates).
		return tx.CreateInBatches(entries, createBatchSize).Error
	})
}

func (r *auditEntryRepository) GetByID(ctx context.Context, id string) (*models.AuditEntry, error) {
	entry := &models.AuditEntry{}
	err := r.pool.DB(ctx, true).First(entry, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (r *auditEntryRepository) List(ctx context.Context, filter *AuditFilter) ([]*models.AuditEntry, error) {
	db := r.pool.DB(ctx, true).Model(&models.AuditEntry{})
	db = applyFilter(db, filter)

	limit := normalizeLimit(filter.Limit)

	if filter.Cursor != "" {
		db = applyPageCursor(db, filter.Cursor)
	}

	var entries []*models.AuditEntry
	err := latestFirst(db).Limit(limit).Find(&entries).Error
	return entries, err
}

func (r *auditEntryRepository) Search(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error) {
	db := r.pool.DB(ctx, true).Model(&models.AuditEntry{})

	searchPattern := "%" + query + "%"
	db = db.Where("action ILIKE ? OR resource_type ILIKE ? OR resource_id ILIKE ? OR service ILIKE ?",
		searchPattern, searchPattern, searchPattern, searchPattern)

	if startDate != nil {
		db = db.Where("created_at >= ?", *startDate)
	}
	if endDate != nil {
		db = db.Where("created_at <= ?", *endDate)
	}
	if cursor != "" {
		db = applyPageCursor(db, cursor)
	}

	var entries []*models.AuditEntry
	err := latestFirst(db).Limit(normalizeLimit(limit)).Find(&entries).Error
	return entries, err
}

func (r *auditEntryRepository) GetLatestHash(ctx context.Context, tenantID string) (string, error) {
	entry := &models.AuditEntry{}
	// Write path: chain tip must not lag a read replica or concurrent batch inserts
	// will fork the hash chain.
	err := r.pool.DB(ctx, false).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC, id DESC").
		First(entry).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", nil
		}
		return "", fmt.Errorf("failed to get latest hash: %w", err)
	}
	return entry.EntryHash, nil
}

func (r *auditEntryRepository) ListChain(ctx context.Context, tenantID string, startDate, endDate *time.Time, limit, offset int) ([]*models.AuditEntry, error) {
	db := r.pool.DB(ctx, true).Model(&models.AuditEntry{}).
		Where("tenant_id = ?", tenantID)

	if startDate != nil {
		db = db.Where("created_at >= ?", *startDate)
	}
	if endDate != nil {
		db = db.Where("created_at <= ?", *endDate)
	}

	var entries []*models.AuditEntry
	err := db.Order("created_at ASC, id ASC").
		Limit(normalizeLimit(limit)).
		Offset(offset).
		Find(&entries).Error
	return entries, err
}

func applyFilter(db *gorm.DB, filter *AuditFilter) *gorm.DB {
	if filter.ProfileID != "" {
		db = db.Where("profile_id = ?", filter.ProfileID)
	}
	if filter.Action != "" {
		db = db.Where("action = ?", filter.Action)
	}
	if filter.ResourceType != "" {
		db = db.Where("resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		db = db.Where("resource_id = ?", filter.ResourceID)
	}
	if filter.Service != "" {
		db = db.Where("service = ?", filter.Service)
	}
	if filter.TargetProfileID != "" {
		db = db.Where("target_profile_id = ?", filter.TargetProfileID)
	}
	if filter.DeviceID != "" {
		db = db.Where("device_id = ?", filter.DeviceID)
	}
	if filter.StartDate != nil {
		db = db.Where("created_at >= ?", *filter.StartDate)
	}
	if filter.EndDate != nil {
		db = db.Where("created_at <= ?", *filter.EndDate)
	}
	return db
}

func applyPageCursor(db *gorm.DB, cursor string) *gorm.DB {
	return db.Where(
		"(created_at, id) < (SELECT created_at, id FROM audit_entries WHERE id = ? ORDER BY created_at DESC LIMIT 1)",
		cursor,
	)
}

func latestFirst(db *gorm.DB) *gorm.DB {
	return db.Order("created_at DESC").Order("id DESC")
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}
