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
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/workerpool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type serviceAccountAuthorizationPolicyRepository struct {
	datastore.BaseRepository[*models.ServiceAccountAuthorizationPolicy]
	pool pool.Pool
}

func (r *serviceAccountAuthorizationPolicyRepository) GetByServiceAccountID(
	ctx context.Context,
	serviceAccountID string,
) (*AuthorizationPolicyState, error) {
	policy := &models.ServiceAccountAuthorizationPolicy{}
	if err := r.pool.DB(ctx, true).
		Where("service_account_id = ?", serviceAccountID).
		First(policy).Error; err != nil {
		return nil, err
	}

	var grants []*models.ServiceAccountAuthorizationGrant
	if err := r.pool.DB(ctx, true).
		Where("policy_id = ?", policy.ID).
		Order("namespace, scope").
		Find(&grants).Error; err != nil {
		return nil, err
	}

	state := &AuthorizationPolicyState{Policy: policy, Grants: make([]AuthorizationGrant, 0, len(grants))}
	for _, grant := range grants {
		var permissions []*models.ServiceAccountAuthorizationPermission
		if err := r.pool.DB(ctx, true).
			Where("grant_id = ?", grant.ID).
			Order("permission").
			Find(&permissions).Error; err != nil {
			return nil, err
		}
		values := make([]string, 0, len(permissions))
		for _, permission := range permissions {
			values = append(values, permission.Permission)
		}
		state.Grants = append(state.Grants, AuthorizationGrant{
			Namespace:   grant.Namespace,
			Scope:       grant.Scope,
			Permissions: values,
		})
	}
	return state, nil
}

func (r *serviceAccountAuthorizationPolicyRepository) ListPending(
	ctx context.Context,
) ([]*models.ServiceAccountAuthorizationPolicy, error) {
	var policies []*models.ServiceAccountAuthorizationPolicy
	err := r.pool.DB(ctx, true).
		Where("status <> ? OR applied_generation <> generation", models.AuthorizationPolicyApplied).
		Order("service_account_id").
		Find(&policies).Error
	return policies, err
}

func (r *serviceAccountAuthorizationPolicyRepository) Replace(
	ctx context.Context,
	serviceAccount *models.ServiceAccount,
	grants []AuthorizationGrant,
) (*models.ServiceAccountAuthorizationPolicy, error) {
	if serviceAccount == nil || serviceAccount.GetID() == "" {
		return nil, fmt.Errorf("replace authorization policy: service account is required")
	}

	var result *models.ServiceAccountAuthorizationPolicy
	err := r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		policy := &models.ServiceAccountAuthorizationPolicy{}
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("service_account_id = ?", serviceAccount.GetID()).
			First(policy).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			policy = &models.ServiceAccountAuthorizationPolicy{
				ServiceAccountID: serviceAccount.GetID(),
				SchemaVersion:    models.AuthorizationPolicySchemaVersion,
				BaseModel: data.BaseModel{
					TenantID:    serviceAccount.TenantID,
					PartitionID: serviceAccount.PartitionID,
				},
			}
		}

		policy.Generation++
		policy.Status = models.AuthorizationPolicyPending
		policy.RetryCount = 0
		policy.LastErrorCode = ""
		policy.LastError = ""
		policy.NextAttemptAt = nil
		if err == gorm.ErrRecordNotFound {
			if createErr := tx.Create(policy).Error; createErr != nil {
				return createErr
			}
		} else if updateErr := tx.Model(policy).Updates(map[string]any{
			"generation":      policy.Generation,
			"status":          policy.Status,
			"retry_count":     0,
			"last_error_code": "",
			"last_error":      "",
			"next_attempt_at": nil,
			"schema_version":  models.AuthorizationPolicySchemaVersion,
		}).Error; updateErr != nil {
			return updateErr
		}

		var oldGrants []*models.ServiceAccountAuthorizationGrant
		if queryErr := tx.Where("policy_id = ?", policy.ID).Find(&oldGrants).Error; queryErr != nil {
			return queryErr
		}
		for _, oldGrant := range oldGrants {
			if deleteErr := tx.Unscoped().Where("grant_id = ?", oldGrant.ID).
				Delete(&models.ServiceAccountAuthorizationPermission{}).Error; deleteErr != nil {
				return deleteErr
			}
		}
		if deleteErr := tx.Unscoped().Where("policy_id = ?", policy.ID).
			Delete(&models.ServiceAccountAuthorizationGrant{}).Error; deleteErr != nil {
			return deleteErr
		}

		grants = slices.Clone(grants)
		slices.SortFunc(grants, func(left, right AuthorizationGrant) int {
			if left.Namespace == right.Namespace {
				return compareStrings(left.Scope, right.Scope)
			}
			return compareStrings(left.Namespace, right.Namespace)
		})
		for _, input := range grants {
			grant := &models.ServiceAccountAuthorizationGrant{
				PolicyID:  policy.ID,
				Namespace: input.Namespace,
				Scope:     input.Scope,
				BaseModel: data.BaseModel{
					TenantID:    serviceAccount.TenantID,
					PartitionID: serviceAccount.PartitionID,
				},
			}
			if createErr := tx.Create(grant).Error; createErr != nil {
				return createErr
			}
			permissions := slices.Clone(input.Permissions)
			slices.Sort(permissions)
			permissions = slices.Compact(permissions)
			for _, value := range permissions {
				permission := &models.ServiceAccountAuthorizationPermission{
					GrantID:    grant.ID,
					Permission: value,
					BaseModel: data.BaseModel{
						TenantID:    serviceAccount.TenantID,
						PartitionID: serviceAccount.PartitionID,
					},
				}
				if createErr := tx.Create(permission).Error; createErr != nil {
					return createErr
				}
			}
		}

		result = policy
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("replace authorization policy for service account %q: %w", serviceAccount.GetID(), err)
	}
	return result, nil
}

func (r *serviceAccountAuthorizationPolicyRepository) ListAppliedTuples(
	ctx context.Context,
	policyID string,
) ([]*models.ServiceAccountAppliedTuple, error) {
	var tuples []*models.ServiceAccountAppliedTuple
	err := r.pool.DB(ctx, true).
		Where("policy_id = ?", policyID).
		Order("namespace, object, relation, subject_namespace, subject_object, subject_relation").
		Find(&tuples).Error
	return tuples, err
}

func (r *serviceAccountAuthorizationPolicyRepository) ReplaceAppliedState(
	ctx context.Context,
	policy *models.ServiceAccountAuthorizationPolicy,
	tuples []*models.ServiceAccountAppliedTuple,
) error {
	if policy == nil || policy.ID == "" {
		return fmt.Errorf("replace applied authorization state: policy is required")
	}

	return r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("policy_id = ?", policy.ID).
			Delete(&models.ServiceAccountAppliedTuple{}).Error; err != nil {
			return err
		}
		for _, tuple := range tuples {
			tuple.PolicyID = policy.ID
			tuple.AppliedGeneration = policy.Generation
			if err := tx.Create(tuple).Error; err != nil {
				return err
			}
		}
		now := time.Now()
		result := tx.Table("service_account_authorization_policies").
			Where("id = ? AND generation = ? AND deleted_at IS NULL", policy.ID, policy.Generation).
			Updates(map[string]any{
				"applied_generation": policy.Generation,
				"status":             models.AuthorizationPolicyApplied,
				"retry_count":        0,
				"last_error_code":    "",
				"last_error":         "",
				"next_attempt_at":    nil,
				"synced_at":          &now,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("replace applied authorization state: policy generation changed")
		}
		return nil
	})
}

func (r *serviceAccountAuthorizationPolicyRepository) RecordFailure(
	ctx context.Context,
	policyID string,
	generation int64,
	code string,
	message string,
	nextAttempt time.Time,
) error {
	result := r.pool.DB(ctx, false).
		Table("service_account_authorization_policies").
		Where("id = ? AND generation = ? AND deleted_at IS NULL", policyID, generation).
		Updates(map[string]any{
			"status":          models.AuthorizationPolicyFailed,
			"retry_count":     gorm.Expr("retry_count + 1"),
			"last_error_code": code,
			"last_error":      message,
			"next_attempt_at": nextAttempt,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("record authorization failure: policy generation changed")
	}
	return nil
}

func NewServiceAccountAuthorizationPolicyRepository(
	ctx context.Context,
	dbPool pool.Pool,
	workMan workerpool.Manager,
) ServiceAccountAuthorizationPolicyRepository {
	return &serviceAccountAuthorizationPolicyRepository{
		BaseRepository: datastore.NewBaseRepository[*models.ServiceAccountAuthorizationPolicy](
			ctx,
			dbPool,
			workMan,
			func() *models.ServiceAccountAuthorizationPolicy {
				return &models.ServiceAccountAuthorizationPolicy{}
			},
		),
		pool: dbPool,
	}
}

func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
