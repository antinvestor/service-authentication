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
	"strings"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/tenancy"
	"github.com/pitabwire/frame/workerpool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type loginEventRepository struct {
	datastore.BaseRepository[*models.LoginEvent]
}

// NewLoginEventRepository creates a new instance of LoginEventRepository
func NewLoginEventRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) LoginEventRepository {
	return &loginEventRepository{
		BaseRepository: datastore.NewBaseRepository[*models.LoginEvent](
			ctx, dbPool, workMan, func() *models.LoginEvent { return &models.LoginEvent{} },
		),
	}
}

// GetByID retrieves a login event by ID
func (r *loginEventRepository) GetByID(ctx context.Context, id string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).
		First(&loginEvent, "id = ?", id).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

// GetByLoginChallenge retrieves a login event by the Hydra login challenge ID
func (r *loginEventRepository) GetByLoginChallenge(ctx context.Context, loginChallengeID string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).
		First(&loginEvent, "login_challenge_id = ?", loginChallengeID).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

// Save creates or updates a login event record
func (r *loginEventRepository) Save(ctx context.Context, loginEvent *models.LoginEvent) error {
	if err := enforceLoginEventWriteTenancy(ctx, loginEvent); err != nil {
		return err
	}
	return r.Pool().DB(ctx, false).Create(loginEvent).Error
}

// Delete removes a login event record by ID
func (r *loginEventRepository) Delete(ctx context.Context, id string) error {
	return scopeLoginEventQuery(ctx, r.Pool().DB(ctx, false)).
		Delete(&models.LoginEvent{}, "id = ?", id).Error
}

// GetMostRecentByProfileID retrieves the most recent login event for a profile
func (r *loginEventRepository) GetMostRecentByProfileID(ctx context.Context, profileID string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).
		Where("profile_id = ?", profileID).
		Order("created_at DESC").
		First(&loginEvent).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

// GetByOauth2SessionID retrieves the login event linked to a Hydra OAuth2 session
func (r *loginEventRepository) GetByOauth2SessionID(ctx context.Context, oauth2SessionID string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).
		Where("oauth2_session_id = ?", oauth2SessionID).
		Order("created_at DESC").
		First(&loginEvent).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

func (r *loginEventRepository) Create(ctx context.Context, loginEvent *models.LoginEvent) error {
	if err := enforceLoginEventWriteTenancy(ctx, loginEvent); err != nil {
		return err
	}
	return r.BaseRepository.Create(ctx, loginEvent)
}

func (r *loginEventRepository) BulkCreate(ctx context.Context, loginEvents []*models.LoginEvent) error {
	if len(loginEvents) == 0 {
		return nil
	}
	for _, loginEvent := range loginEvents {
		if err := enforceLoginEventWriteTenancy(ctx, loginEvent); err != nil {
			return err
		}
	}
	return r.Pool().DB(ctx, false).
		Clauses(clause.OnConflict{DoNothing: true}).
		CreateInBatches(loginEvents, r.BatchSize()).Error
}

func (r *loginEventRepository) Update(
	ctx context.Context,
	loginEvent *models.LoginEvent,
	affectedFields ...string,
) (int64, error) {
	if loginEvent.GetID() == "" {
		return 0, errors.New("entity ID is required")
	}
	if err := enforceLoginEventWriteTenancy(ctx, loginEvent); err != nil {
		return 0, err
	}
	if len(affectedFields) > 0 {
		for _, field := range affectedFields {
			if err := r.IsFieldAllowed(field); err != nil {
				return 0, err
			}
		}
	}

	query := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, false)).
		Model(loginEvent).
		Where("id = ? AND version = ?", loginEvent.GetID(), loginEvent.GetVersion())
	if len(affectedFields) > 0 {
		query = query.Select(affectedFields)
	} else {
		query = query.Omit(r.FieldsImmutable()...)
	}

	result := query.Updates(loginEvent)
	return result.RowsAffected, result.Error
}

func (r *loginEventRepository) BulkUpdate(
	ctx context.Context,
	entityIDs []string,
	params map[string]any,
) (int64, error) {
	if len(entityIDs) == 0 {
		return 0, nil
	}
	if len(params) == 0 {
		return 0, errors.New("no parameters provided for update")
	}
	for column := range params {
		if err := r.IsFieldAllowed(column); err != nil {
			return 0, err
		}
		for _, immutable := range r.FieldsImmutable() {
			if strings.EqualFold(column, immutable) {
				return 0, fmt.Errorf("cannot bulk update immutable field: %s", column)
			}
		}
	}

	result := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, false)).
		Table("login_events").
		Where("id IN ?", entityIDs).
		Updates(params)
	return result.RowsAffected, result.Error
}

func (r *loginEventRepository) DeleteBatch(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return scopeLoginEventQuery(ctx, r.Pool().DB(ctx, false)).
		Where("id IN ?", ids).
		Delete(&models.LoginEvent{}).Error
}

func (r *loginEventRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).
		Table("login_events").
		Count(&count).Error
	return count, err
}

func (r *loginEventRepository) CountBy(ctx context.Context, properties map[string]any) (int64, error) {
	var count int64
	query := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).Table("login_events")
	for key, value := range properties {
		if err := r.IsFieldAllowed(key); err != nil {
			return 0, err
		}
		query = query.Where(key+" = ?", value)
	}
	err := query.Count(&count).Error
	return count, err
}

func (r *loginEventRepository) GetLastestBy(ctx context.Context, properties map[string]any) (*models.LoginEvent, error) {
	loginEvent := &models.LoginEvent{}
	query := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true))
	for key, value := range properties {
		if err := r.IsFieldAllowed(key); err != nil {
			return nil, err
		}
		query = query.Where(key+" = ?", value)
	}
	err := query.Order("created_at DESC").First(loginEvent).Error
	if err != nil {
		return nil, err
	}
	return loginEvent, nil
}

func (r *loginEventRepository) GetAllBy(
	ctx context.Context,
	properties map[string]any,
	offset, limit int,
) ([]*models.LoginEvent, error) {
	var loginEvents []*models.LoginEvent
	query := scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)).Offset(offset)
	if limit > 0 {
		query = query.Limit(limit)
	}
	for key, value := range properties {
		if err := r.IsFieldAllowed(key); err != nil {
			return nil, err
		}
		query = query.Where(key+" = ?", value)
	}
	err := query.Find(&loginEvents).Error
	return loginEvents, err
}

func (r *loginEventRepository) Search(
	ctx context.Context,
	query *data.SearchQuery,
) (workerpool.JobResultPipe[[]*models.LoginEvent], error) {
	return data.StableSearch[*models.LoginEvent](
		ctx,
		r.WorkManager(),
		query,
		func(ctx context.Context, query *data.SearchQuery) ([]*models.LoginEvent, error) {
			return datastore.SearchFunc[*models.LoginEvent](
				ctx,
				scopeLoginEventQuery(ctx, r.Pool().DB(ctx, true)),
				query,
				r.IsFieldAllowed,
			)
		},
	)
}

func scopeLoginEventQuery(ctx context.Context, db *gorm.DB) *gorm.DB {
	claims := tenancy.ClaimsFromContext(ctx)
	if claims == nil || claims.IsEmpty() || claims.Skip {
		return db
	}
	if claims.TenantID != "" {
		db = db.Where("tenant_id = ?", claims.TenantID)
	}
	if len(claims.PartitionIDs) > 0 {
		db = db.Where("partition_id IN ?", claims.PartitionIDs)
	}
	return db
}

func enforceLoginEventWriteTenancy(ctx context.Context, loginEvent *models.LoginEvent) error {
	if loginEvent == nil {
		return errors.New("login event is nil")
	}
	claims := tenancy.ClaimsFromContext(ctx)
	if claims == nil || claims.IsEmpty() || claims.Skip {
		return nil
	}
	if claims.TenantID != "" {
		if loginEvent.TenantID != "" && loginEvent.TenantID != claims.TenantID {
			return fmt.Errorf("login event tenant %q does not match context tenant %q", loginEvent.TenantID, claims.TenantID)
		}
		loginEvent.TenantID = claims.TenantID
	}
	if len(claims.PartitionIDs) == 0 {
		return nil
	}
	if loginEvent.PartitionID == "" {
		loginEvent.PartitionID = claims.PartitionIDs[0]
		return nil
	}
	for _, partitionID := range claims.PartitionIDs {
		if loginEvent.PartitionID == partitionID {
			return nil
		}
	}
	return fmt.Errorf("login event partition %q is not allowed by context", loginEvent.PartitionID)
}
