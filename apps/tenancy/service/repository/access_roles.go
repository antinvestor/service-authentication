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

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type accessRoleRepository struct {
	datastore.BaseRepository[*models.AccessRole]
}

func (ar *accessRoleRepository) GetByAccessID(ctx context.Context, accessID string) ([]*models.AccessRole, error) {
	accessRoles := make([]*models.AccessRole, 0)
	err := ar.Pool().DB(ctx, true).
		Find(&accessRoles, " access_id = ?", accessID).Error

	return accessRoles, err
}

func NewAccessRoleRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) AccessRoleRepository {
	return &accessRoleRepository{
		BaseRepository: datastore.NewBaseRepository[*models.AccessRole](
			ctx, dbPool, workMan, func() *models.AccessRole { return &models.AccessRole{} },
		),
	}
}
