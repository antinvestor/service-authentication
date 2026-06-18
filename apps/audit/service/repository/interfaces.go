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

// AuditEntryRepository is the append-only data access interface for audit entries.
// By design, no Update or Delete methods are exposed.
type AuditEntryRepository interface {
	// Create persists a new audit entry. The caller must set EntryHash,
	// PreviousHash, and Signature before calling Create.
	Create(ctx context.Context, entry *models.AuditEntry) error

	// CreateBatch persists multiple audit entries atomically.
	CreateBatch(ctx context.Context, entries []*models.AuditEntry) error

	// GetByID retrieves a single audit entry by primary key.
	GetByID(ctx context.Context, id string) (*models.AuditEntry, error)

	// List retrieves audit entries matching the given filter with cursor-based pagination.
	List(ctx context.Context, filter *AuditFilter) ([]*models.AuditEntry, error)

	// Search performs free-text search across audit entries.
	Search(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error)

	// GetLatestHash retrieves the EntryHash of the most recent audit entry
	// for the given tenant. Returns empty string if no entries exist.
	GetLatestHash(ctx context.Context, tenantID string) (string, error)

	// ListChain retrieves entries in creation order for integrity verification.
	// Results are ordered by created_at ASC.
	ListChain(ctx context.Context, tenantID string, startDate, endDate *time.Time, limit, offset int) ([]*models.AuditEntry, error)
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
	StartDate       *time.Time
	EndDate         *time.Time
	Limit           int
	Cursor          string // ID of the last entry from the previous page
}
