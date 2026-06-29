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
	"slices"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/workerpool"
	"gorm.io/gorm"
)

type oauthClientRecipientRepository struct {
	datastore.BaseRepository[*models.OAuthClientRecipient]
	pool pool.Pool
}

func (r *oauthClientRecipientRepository) ListByClientRef(
	ctx context.Context,
	clientRef string,
) ([]*models.OAuthClientRecipient, error) {
	var recipients []*models.OAuthClientRecipient
	err := r.pool.DB(ctx, true).
		Where("client_ref = ?", clientRef).
		Order("resource_audience").
		Find(&recipients).Error
	return recipients, err
}

func (r *oauthClientRecipientRepository) ReplaceForClient(
	ctx context.Context,
	client *models.Client,
	audiences []string,
) error {
	if client == nil || client.GetID() == "" {
		return fmt.Errorf("replace OAuth recipients: client is required")
	}

	audiences = slices.Clone(audiences)
	slices.Sort(audiences)
	audiences = slices.Compact(audiences)

	return r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("client_ref = ?", client.GetID()).
			Delete(&models.OAuthClientRecipient{}).Error; err != nil {
			return fmt.Errorf("delete OAuth recipients for client %q: %w", client.GetID(), err)
		}

		for _, audience := range audiences {
			recipient := &models.OAuthClientRecipient{
				ClientRef:        client.GetID(),
				ResourceAudience: audience,
				BaseModel: data.BaseModel{
					TenantID:    client.TenantID,
					PartitionID: client.PartitionID,
				},
			}
			if err := tx.Create(recipient).Error; err != nil {
				return fmt.Errorf("create OAuth recipient %q for client %q: %w", audience, client.GetID(), err)
			}
		}
		return nil
	})
}

func NewOAuthClientRecipientRepository(
	ctx context.Context,
	dbPool pool.Pool,
	workMan workerpool.Manager,
) OAuthClientRecipientRepository {
	return &oauthClientRecipientRepository{
		BaseRepository: datastore.NewBaseRepository[*models.OAuthClientRecipient](
			ctx,
			dbPool,
			workMan,
			func() *models.OAuthClientRecipient { return &models.OAuthClientRecipient{} },
		),
		pool: dbPool,
	}
}
