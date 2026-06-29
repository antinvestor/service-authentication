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

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/workerpool"
)

type loginRepository struct {
	datastore.BaseRepository[*models.Login]
}

// NewLoginRepository creates a new instance of LoginRepository
func NewLoginRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) LoginRepository {
	return &loginRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Login](
			ctx, dbPool, workMan, func() *models.Login { return &models.Login{} },
		),
	}
}

// GetByID retrieves a login by ID
func (r *loginRepository) GetByID(ctx context.Context, id string) (*models.Login, error) {
	var login models.Login
	err := r.Pool().DB(ctx, true).First(&login, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &login, nil
}

// GetByProfileID retrieves a login by profile ID
func (r *loginRepository) GetByProfileID(ctx context.Context, profileID string) (*models.Login, error) {
	var login models.Login
	err := r.Pool().DB(ctx, true).First(&login, "profile_id = ?", profileID).Error
	if err != nil {
		return nil, err
	}
	return &login, nil
}

// Save creates or updates a login record
func (r *loginRepository) Save(ctx context.Context, login *models.Login) error {
	if login.ID == "" {
		// Create new record
		return r.Pool().DB(ctx, false).Create(login).Error
	}
	// Update existing record
	return r.Pool().DB(ctx, false).Save(login).Error
}
