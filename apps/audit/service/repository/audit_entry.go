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
	"github.com/pitabwire/frame/v2/datastore/pool"
	"gorm.io/gorm"
)

const defaultLimit = 50
const maxLimit = 500

type auditEntryRepository struct {
	pool pool.Pool
}

// NewAuditEntryRepository creates the read-side entry repository.
func NewAuditEntryRepository(dbPool pool.Pool) AuditEntryRepository {
	return &auditEntryRepository{pool: dbPool}
}

func (r *auditEntryRepository) GetByID(ctx context.Context, id string) (*models.AuditEntry, error) {
	entry := &models.AuditEntry{}
	err := r.pool.DB(ctx, true).First(entry, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (r *auditEntryRepository) GetBySeq(ctx context.Context, tenantID string, seq int64) (*models.AuditEntry, error) {
	entry := &models.AuditEntry{}
	err := r.pool.DB(tenantScope(ctx, tenantID), true).Where("tenant_id = ? AND seq = ?", tenantID, seq).First(entry).Error
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (r *auditEntryRepository) List(ctx context.Context, filter *AuditFilter) ([]*models.AuditEntry, error) {
	db := r.pool.DB(ctx, true).Model(&models.AuditEntry{})
	db = applyFilter(db, filter)
	limit := normalizeLimit(filter.Limit)

	var entries []*models.AuditEntry
	if filter.BySeq() {
		if filter.Cursor != "" {
			db = db.Where("seq > (SELECT seq FROM audit_entries WHERE id = ? LIMIT 1)", filter.Cursor)
		}
		err := db.Order("seq ASC").Limit(limit).Find(&entries).Error
		return entries, err
	}
	if filter.Cursor != "" {
		db = applyPageCursor(db, filter.Cursor)
	}
	err := latestFirst(db).Limit(limit).Find(&entries).Error
	return entries, err
}

// Search matches a prefix on the indexed action, resource_type, resource_id
// and service columns. Callers bound the time window (see handler).
func (r *auditEntryRepository) Search(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error) {
	db := r.pool.DB(ctx, true).Model(&models.AuditEntry{})

	pattern := query + "%"
	db = db.Where("action ILIKE ? OR resource_type ILIKE ? OR resource_id ILIKE ? OR service ILIKE ?",
		pattern, pattern, pattern, pattern)

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

func (r *auditEntryRepository) ListChainBySeq(ctx context.Context, tenantID string, fromSeq, toSeq int64, limit int) ([]*models.AuditEntry, error) {
	db := r.pool.DB(tenantScope(ctx, tenantID), true).Model(&models.AuditEntry{}).
		Where("tenant_id = ? AND seq >= ?", tenantID, fromSeq)
	if toSeq > 0 {
		db = db.Where("seq <= ?", toSeq)
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var entries []*models.AuditEntry
	err := db.Order("seq ASC").Limit(limit).Find(&entries).Error
	return entries, err
}

func (r *auditEntryRepository) SeqAtOrAfter(ctx context.Context, tenantID string, t time.Time) (int64, error) {
	return r.seqBoundary(ctx, tenantID, "created_at >= ?", "seq ASC", t)
}

func (r *auditEntryRepository) SeqAtOrBefore(ctx context.Context, tenantID string, t time.Time) (int64, error) {
	return r.seqBoundary(ctx, tenantID, "created_at <= ?", "seq DESC", t)
}

func (r *auditEntryRepository) seqBoundary(ctx context.Context, tenantID, cond, order string, t time.Time) (int64, error) {
	var row models.AuditEntry
	err := r.pool.DB(tenantScope(ctx, tenantID), true).Select("seq").Where("tenant_id = ?", tenantID).Where(cond, t).
		Order(order).Limit(1).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, err
	}
	return row.Seq, nil
}

func applyFilter(db *gorm.DB, filter *AuditFilter) *gorm.DB {
	eq := map[string]string{
		"profile_id": filter.ProfileID, "action": filter.Action, "resource_type": filter.ResourceType,
		"resource_id": filter.ResourceID, "service": filter.Service, "target_profile_id": filter.TargetProfileID,
		"device_id": filter.DeviceID, "intent_id": filter.IntentID, "event_id": filter.EventID,
		"correlation_id": filter.CorrelationID, "on_behalf_of": filter.OnBehalfOf,
	}
	for _, col := range []string{"profile_id", "action", "resource_type", "resource_id", "service",
		"target_profile_id", "device_id", "intent_id", "event_id", "correlation_id", "on_behalf_of"} {
		if v := eq[col]; v != "" {
			db = db.Where(col+" = ?", v)
		}
	}
	if filter.SeqFrom > 0 {
		db = db.Where("seq >= ?", filter.SeqFrom)
	}
	if filter.SeqTo > 0 {
		db = db.Where("seq <= ?", filter.SeqTo)
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
