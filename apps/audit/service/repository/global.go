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
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/tenancy"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Signing keys (global, unscoped)
// ---------------------------------------------------------------------------

type signingKeyRepository struct {
	datastore.BaseRepository[*models.AuditSigningKey]
}

// NewSigningKeyRepository creates the global signing key repository.
func NewSigningKeyRepository(ctx context.Context, dbPool pool.Pool) SigningKeyRepository {
	return &signingKeyRepository{
		BaseRepository: datastore.NewBaseRepository[*models.AuditSigningKey](ctx, dbPool, nil,
			func() *models.AuditSigningKey { return &models.AuditSigningKey{} }),
	}
}

func (r *signingKeyRepository) GetByKeyID(ctx context.Context, keyID string) (*models.AuditSigningKey, error) {
	key := &models.AuditSigningKey{}
	err := r.Pool().DB(ctx, false).Where("key_id = ?", keyID).First(key).Error
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (r *signingKeyRepository) List(ctx context.Context) ([]*models.AuditSigningKey, error) {
	var keys []*models.AuditSigningKey
	err := r.Pool().DB(ctx, true).Order("valid_from ASC, key_id ASC").Find(&keys).Error
	return keys, err
}

func (r *signingKeyRepository) Retire(ctx context.Context, keyID string, at time.Time) error {
	res := r.Pool().DB(ctx, false).Table(models.AuditSigningKey{}.TableName()).
		Where("key_id = ? AND retired_at IS NULL", keyID).
		Updates(map[string]any{"retired_at": at, "modified_at": at})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("signing key %q: %w", keyID, ErrAlreadyRetiredOrMissing)
	}
	return nil
}

// ErrAlreadyRetiredOrMissing is returned by Retire when nothing changed.
var ErrAlreadyRetiredOrMissing = errors.New("key is already retired or does not exist")

// ---------------------------------------------------------------------------
// Manifests (global, unscoped)
// ---------------------------------------------------------------------------

type manifestRepository struct {
	datastore.BaseRepository[*models.AuditManifest]
}

// NewManifestRepository creates the global manifest repository.
func NewManifestRepository(ctx context.Context, dbPool pool.Pool) ManifestRepository {
	return &manifestRepository{
		BaseRepository: datastore.NewBaseRepository[*models.AuditManifest](ctx, dbPool, nil,
			func() *models.AuditManifest { return &models.AuditManifest{} }),
	}
}

func (r *manifestRepository) Latest(ctx context.Context, service string) (*models.AuditManifest, error) {
	m := &models.AuditManifest{}
	err := r.Pool().DB(ctx, false).Where("service = ?", service).
		Order("manifest_version DESC").First(m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Chain heads (read side)
// ---------------------------------------------------------------------------

type chainHeadRepository struct {
	pool pool.Pool
}

// NewChainHeadRepository creates the read-side head repository.
func NewChainHeadRepository(dbPool pool.Pool) ChainHeadRepository {
	return &chainHeadRepository{pool: dbPool}
}

// tenantScope binds the connection to the whole tenant, regardless of the
// caller's partition. The chain, its head and its checkpoints are
// tenant-level structures that span every partition of the tenant.
func tenantScope(ctx context.Context, tenantID string) context.Context {
	return tenancy.WithSystemPrincipal(ctx, tenancy.SystemPrincipal{
		ServiceName: "service_audit", TenantID: tenantID, Reason: "chain-read",
	})
}

func (r *chainHeadRepository) Get(ctx context.Context, tenantID string) (*models.AuditChainHead, error) {
	head := &models.AuditChainHead{}
	err := r.pool.DB(tenantScope(ctx, tenantID), false).Where("id = ?", tenantID).First(head).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &models.AuditChainHead{}, nil
		}
		return nil, err
	}
	return head, nil
}
