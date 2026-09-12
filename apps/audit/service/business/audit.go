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
	"errors"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
)

// ErrSearchWindowRequired is returned when a search has no bounded window.
var ErrSearchWindowRequired = errors.New("search requires start_date and end_date spanning at most 31 days")

// MaxSearchWindow bounds free-text search so it never scans the table.
const MaxSearchWindow = 31 * 24 * time.Hour

// ReadBusiness is the query side of the audit service.
type ReadBusiness interface {
	GetEntry(ctx context.Context, id string) (*models.AuditEntry, error)
	ListEntries(ctx context.Context, filter *repository.AuditFilter) ([]*models.AuditEntry, error)
	SearchEntries(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error)
	ListCheckpoints(ctx context.Context, tenantID string, fromSeq, toSeq int64, limit int) ([]*models.AuditCheckpoint, error)
	Head(ctx context.Context, tenantID string) (*models.AuditChainHead, error)
}

type readBusiness struct {
	entries     repository.AuditEntryRepository
	checkpoints repository.CheckpointRepository
	heads       repository.ChainHeadRepository
}

// NewReadBusiness creates the query-side business layer.
func NewReadBusiness(entries repository.AuditEntryRepository, checkpoints repository.CheckpointRepository, heads repository.ChainHeadRepository) ReadBusiness {
	return &readBusiness{entries: entries, checkpoints: checkpoints, heads: heads}
}

func (rb *readBusiness) GetEntry(ctx context.Context, id string) (*models.AuditEntry, error) {
	return rb.entries.GetByID(ctx, id)
}

func (rb *readBusiness) ListEntries(ctx context.Context, filter *repository.AuditFilter) ([]*models.AuditEntry, error) {
	return rb.entries.List(ctx, filter)
}

func (rb *readBusiness) SearchEntries(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error) {
	if startDate == nil || endDate == nil || endDate.Before(*startDate) || endDate.Sub(*startDate) > MaxSearchWindow {
		return nil, ErrSearchWindowRequired
	}
	return rb.entries.Search(ctx, query, startDate, endDate, limit, cursor)
}

func (rb *readBusiness) ListCheckpoints(ctx context.Context, tenantID string, fromSeq, toSeq int64, limit int) ([]*models.AuditCheckpoint, error) {
	return rb.checkpoints.List(ctx, tenantID, fromSeq, toSeq, limit)
}

func (rb *readBusiness) Head(ctx context.Context, tenantID string) (*models.AuditChainHead, error) {
	return rb.heads.Get(ctx, tenantID)
}
