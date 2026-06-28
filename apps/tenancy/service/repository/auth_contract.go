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
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore/pool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type authContractRepository struct {
	pool pool.Pool
}

func (r *authContractRepository) CreateOAuthClient(
	ctx context.Context,
	client *models.Client,
	recipients []string,
) error {
	if client == nil {
		return fmt.Errorf("create OAuth client: client is required")
	}
	return r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(client).Error; err != nil {
			return fmt.Errorf("create OAuth client: %w", err)
		}
		return createOAuthRecipients(tx, client, recipients)
	})
}

func (r *authContractRepository) CreateServiceAccount(
	ctx context.Context,
	serviceAccount *models.ServiceAccount,
	client *models.Client,
	recipients []string,
	grants []AuthorizationGrant,
) (*models.ServiceAccountAuthorizationPolicy, error) {
	if serviceAccount == nil || client == nil {
		return nil, fmt.Errorf("create service account: service account and OAuth client are required")
	}

	var policy *models.ServiceAccountAuthorizationPolicy
	err := r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(client).Error; err != nil {
			return fmt.Errorf("create service-account OAuth client: %w", err)
		}
		serviceAccount.ClientID = client.ClientID
		serviceAccount.ClientRef = client.ID
		if err := tx.Create(serviceAccount).Error; err != nil {
			return fmt.Errorf("create service account: %w", err)
		}
		client.ServiceAccountID = serviceAccount.ID
		if err := tx.Model(client).Update("service_account_id", serviceAccount.ID).Error; err != nil {
			return fmt.Errorf("link OAuth client to service account: %w", err)
		}
		if err := createOAuthRecipients(tx, client, recipients); err != nil {
			return err
		}

		policy = &models.ServiceAccountAuthorizationPolicy{
			ServiceAccountID: serviceAccount.ID,
			SchemaVersion:    models.AuthorizationPolicySchemaVersion,
			Generation:       1,
			Status:           models.AuthorizationPolicyPending,
			BaseModel: data.BaseModel{
				TenantID:    serviceAccount.TenantID,
				PartitionID: serviceAccount.PartitionID,
			},
		}
		if err := tx.Create(policy).Error; err != nil {
			return fmt.Errorf("create service-account authorization policy: %w", err)
		}
		if err := createAuthorizationGrants(tx, serviceAccount, policy, grants); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (r *authContractRepository) UpdateOAuthClient(
	ctx context.Context,
	client *models.Client,
	fields []string,
	recipients []string,
) error {
	if client == nil || client.ID == "" {
		return fmt.Errorf("update OAuth client: client is required")
	}
	return r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		if len(fields) > 0 {
			if err := tx.Model(client).Select(fields).Updates(client).Error; err != nil {
				return fmt.Errorf("update OAuth client: %w", err)
			}
		}
		if err := tx.Unscoped().Where("client_ref = ?", client.ID).
			Delete(&models.OAuthClientRecipient{}).Error; err != nil {
			return fmt.Errorf("replace OAuth recipients: %w", err)
		}
		return createOAuthRecipients(tx, client, recipients)
	})
}

func (r *authContractRepository) UpdateServiceAccount(
	ctx context.Context,
	serviceAccount *models.ServiceAccount,
	serviceAccountFields []string,
	client *models.Client,
	clientFields []string,
	recipients []string,
	replaceRecipients bool,
	grants []AuthorizationGrant,
	replacePolicy bool,
) (*models.ServiceAccountAuthorizationPolicy, error) {
	if serviceAccount == nil || serviceAccount.ID == "" || client == nil || client.ID == "" {
		return nil, fmt.Errorf("update service account: service account and OAuth client are required")
	}

	var policy *models.ServiceAccountAuthorizationPolicy
	err := r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		if len(serviceAccountFields) > 0 {
			if err := tx.Model(serviceAccount).Select(serviceAccountFields).Updates(serviceAccount).Error; err != nil {
				return fmt.Errorf("update service account identity: %w", err)
			}
		}
		if len(clientFields) > 0 {
			if err := tx.Model(client).Select(clientFields).Updates(client).Error; err != nil {
				return fmt.Errorf("update service-account OAuth client: %w", err)
			}
		}
		if replaceRecipients {
			if err := tx.Unscoped().Where("client_ref = ?", client.ID).
				Delete(&models.OAuthClientRecipient{}).Error; err != nil {
				return fmt.Errorf("replace service-account OAuth recipients: %w", err)
			}
			if err := createOAuthRecipients(tx, client, recipients); err != nil {
				return err
			}
		}

		policy = &models.ServiceAccountAuthorizationPolicy{}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("service_account_id = ?", serviceAccount.ID).
			First(policy).Error; err != nil {
			return fmt.Errorf("load service-account authorization policy: %w", err)
		}
		if !replacePolicy {
			return nil
		}

		var oldGrants []*models.ServiceAccountAuthorizationGrant
		if err := tx.Where("policy_id = ?", policy.ID).Find(&oldGrants).Error; err != nil {
			return err
		}
		for _, oldGrant := range oldGrants {
			if err := tx.Unscoped().Where("grant_id = ?", oldGrant.ID).
				Delete(&models.ServiceAccountAuthorizationPermission{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Unscoped().Where("policy_id = ?", policy.ID).
			Delete(&models.ServiceAccountAuthorizationGrant{}).Error; err != nil {
			return err
		}

		policy.Generation++
		policy.Status = models.AuthorizationPolicyPending
		if err := tx.Model(policy).Updates(map[string]any{
			"generation":      policy.Generation,
			"status":          policy.Status,
			"retry_count":     0,
			"last_error_code": "",
			"last_error":      "",
			"next_attempt_at": nil,
		}).Error; err != nil {
			return err
		}
		return createAuthorizationGrants(tx, serviceAccount, policy, grants)
	})
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func (r *authContractRepository) FinalizeServiceAccountRemoval(
	ctx context.Context,
	serviceAccountID string,
) (string, error) {
	clientID := ""
	err := r.pool.DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		client := &models.Client{}
		if err := tx.Where("service_account_id = ?", serviceAccountID).First(client).Error; err != nil {
			return fmt.Errorf("load service-account OAuth client for removal: %w", err)
		}
		clientID = client.ID
		if err := tx.Unscoped().Where("client_ref = ?", client.ID).
			Delete(&models.OAuthClientRecipient{}).Error; err != nil {
			return fmt.Errorf("remove service-account OAuth recipients: %w", err)
		}
		if err := tx.Delete(client).Error; err != nil {
			return fmt.Errorf("remove service-account OAuth client: %w", err)
		}
		if err := tx.Delete(&models.ServiceAccount{}, "id = ?", serviceAccountID).Error; err != nil {
			return fmt.Errorf("remove service account: %w", err)
		}
		return nil
	})
	return clientID, err
}

func createOAuthRecipients(tx *gorm.DB, client *models.Client, recipients []string) error {
	recipients = slices.Clone(recipients)
	slices.Sort(recipients)
	recipients = slices.Compact(recipients)
	for _, audience := range recipients {
		recipient := &models.OAuthClientRecipient{
			ClientRef:        client.ID,
			ResourceAudience: audience,
			BaseModel: data.BaseModel{
				TenantID:    client.TenantID,
				PartitionID: client.PartitionID,
			},
		}
		if err := tx.Create(recipient).Error; err != nil {
			return fmt.Errorf("create OAuth client recipient %q: %w", audience, err)
		}
	}
	return nil
}

func createAuthorizationGrants(
	tx *gorm.DB,
	serviceAccount *models.ServiceAccount,
	policy *models.ServiceAccountAuthorizationPolicy,
	grants []AuthorizationGrant,
) error {
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
		if err := tx.Create(grant).Error; err != nil {
			return fmt.Errorf("create authorization grant %q: %w", input.Namespace, err)
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
			if err := tx.Create(permission).Error; err != nil {
				return fmt.Errorf("create authorization permission %q/%q: %w", input.Namespace, value, err)
			}
		}
	}
	return nil
}

func NewAuthContractRepository(dbPool pool.Pool) AuthContractRepository {
	return &authContractRepository{pool: dbPool}
}
