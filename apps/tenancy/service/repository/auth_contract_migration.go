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
	"slices"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthContractMigrationExpectations struct {
	Clients         int64
	ServiceAccounts int64
	Recipients      int64
	Grants          int64
}

type legacyClientAuthContract struct {
	ID          string
	TenantID    string
	PartitionID string
	Audiences   data.JSONMap
}

type legacyServiceAccountAuthContract struct {
	ID          string
	TenantID    string
	PartitionID string
	Audiences   data.JSONMap
}

// MigrateAuthContractV2 performs the destructive, one-time split of OAuth
// recipients and service-account authorization grants. It is idempotent: once
// the legacy columns are gone, subsequent executions only validate target
// state. Unknown recipients, namespaces, and permissions fail the transaction.
func MigrateAuthContractV2(
	ctx context.Context,
	dbPool pool.Pool,
	audienceBaseURL string,
	expected AuthContractMigrationExpectations,
) error {
	if dbPool == nil {
		return errors.New("auth contract migration: datastore pool is not initialised")
	}

	baseURL, err := config.ParseAudienceBaseURL(audienceBaseURL)
	if err != nil {
		return fmt.Errorf("auth contract migration: %w", err)
	}

	db := dbPool.DB(ctx, false)
	if db == nil {
		return errors.New("auth contract migration: writable database is not configured")
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if lockErr := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "auth-contract-v2").Error; lockErr != nil {
			return fmt.Errorf("lock auth contract migration: %w", lockErr)
		}

		clientLegacy, columnErr := hasColumn(tx, "clients", "audiences")
		if columnErr != nil {
			return columnErr
		}
		serviceAccountLegacy, columnErr := hasColumn(tx, "service_accounts", "audiences")
		if columnErr != nil {
			return columnErr
		}

		if !clientLegacy && !serviceAccountLegacy {
			return validateMigratedAuthContract(tx, AuthContractMigrationExpectations{
				Clients:         -1,
				ServiceAccounts: -1,
				Recipients:      -1,
				Grants:          -1,
			})
		}
		if !clientLegacy || !serviceAccountLegacy {
			return errors.New("auth contract migration: legacy audience columns are partially removed")
		}
		if backfillErr := tx.Exec(`
			UPDATE service_accounts AS service_account
			SET name = regexp_replace(client.name, '^sa-', '')
			FROM clients AS client
			WHERE client.id = service_account.client_ref
			  AND service_account.name = ''
		`).Error; backfillErr != nil {
			return fmt.Errorf("backfill service account names: %w", backfillErr)
		}

		var clients []legacyClientAuthContract
		if queryErr := tx.Table("clients").
			Select("id", "tenant_id", "partition_id", "audiences").
			Where("deleted_at IS NULL").
			Order("id").
			Find(&clients).Error; queryErr != nil {
			return fmt.Errorf("read legacy OAuth clients: %w", queryErr)
		}
		if assertErr := assertExpected("clients", int64(len(clients)), expected.Clients); assertErr != nil {
			return assertErr
		}

		legacyRecipientCount := int64(0)
		for _, client := range clients {
			legacyRecipientCount += int64(len(client.Audiences))
			if migrateErr := migrateClientRecipients(tx, client, string(baseURL)); migrateErr != nil {
				return migrateErr
			}
		}
		if assertErr := assertExpected("legacy recipient entries", legacyRecipientCount, expected.Recipients); assertErr != nil {
			return assertErr
		}

		var serviceAccounts []legacyServiceAccountAuthContract
		if queryErr := tx.Table("service_accounts").
			Select("id", "tenant_id", "partition_id", "audiences").
			Where("deleted_at IS NULL").
			Order("id").
			Find(&serviceAccounts).Error; queryErr != nil {
			return fmt.Errorf("read legacy service accounts: %w", queryErr)
		}
		if assertErr := assertExpected("service accounts", int64(len(serviceAccounts)), expected.ServiceAccounts); assertErr != nil {
			return assertErr
		}

		grantCount := int64(0)
		for _, serviceAccount := range serviceAccounts {
			migratedGrants, migrateErr := migrateServiceAccountPolicy(tx, serviceAccount)
			if migrateErr != nil {
				return migrateErr
			}
			grantCount += migratedGrants
		}
		if assertErr := assertExpected("authorization grants", grantCount, expected.Grants); assertErr != nil {
			return assertErr
		}

		for _, statement := range []string{
			"ALTER TABLE clients DROP COLUMN audiences",
			"ALTER TABLE clients DROP COLUMN roles",
			"ALTER TABLE service_accounts DROP COLUMN audiences",
			"ALTER TABLE service_accounts DROP COLUMN client_secret",
		} {
			if execErr := tx.Exec(statement).Error; execErr != nil {
				return fmt.Errorf("remove legacy auth contract column: %w", execErr)
			}
		}

		return validateMigratedAuthContract(tx, expected)
	})
}

func migrateClientRecipients(tx *gorm.DB, client legacyClientAuthContract, baseURL string) error {
	legacyRecipients := make([]string, 0, len(client.Audiences))
	for recipient := range client.Audiences {
		legacyRecipients = append(legacyRecipients, recipient)
	}
	slices.Sort(legacyRecipients)

	for _, recipient := range legacyRecipients {
		audiencePath, ok := authz.LegacyRecipientAudiencePath(recipient)
		if !ok {
			return fmt.Errorf("client %q has unmapped OAuth recipient %q", client.ID, recipient)
		}
		audience, parseErr := config.ParseResourceAudience(baseURL + audiencePath)
		if parseErr != nil {
			return fmt.Errorf("client %q recipient %q: %w", client.ID, recipient, parseErr)
		}

		model := &models.OAuthClientRecipient{
			ClientRef:        client.ID,
			ResourceAudience: string(audience),
			BaseModel: data.BaseModel{
				TenantID:    client.TenantID,
				PartitionID: client.PartitionID,
			},
		}
		if createErr := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(model).Error; createErr != nil {
			return fmt.Errorf("migrate client %q recipient %q: %w", client.ID, recipient, createErr)
		}
	}
	return nil
}

func migrateServiceAccountPolicy(
	tx *gorm.DB,
	serviceAccount legacyServiceAccountAuthContract,
) (int64, error) {
	requested := authz.ParseAudiencePermissions(serviceAccount.Audiences)
	functional := authz.SelectRegisteredServiceGrants(requested, authz.DeployedServiceNamespaceRecords())
	resolved, err := authz.ResolveServiceGrants(functional, authz.DeployedServiceNamespaceRecords())
	if err != nil {
		return 0, fmt.Errorf("service account %q policy: %w", serviceAccount.ID, err)
	}

	policy := &models.ServiceAccountAuthorizationPolicy{
		ServiceAccountID: serviceAccount.ID,
		SchemaVersion:    models.AuthorizationPolicySchemaVersion,
		Generation:       1,
		Status:           models.AuthorizationPolicyPending,
		BaseModel: data.BaseModel{
			TenantID:    serviceAccount.TenantID,
			PartitionID: serviceAccount.PartitionID,
		},
	}
	if createErr := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(policy).Error; createErr != nil {
		return 0, fmt.Errorf("create service account %q policy: %w", serviceAccount.ID, createErr)
	}
	policy.ID = ""
	if lookupErr := tx.Where("service_account_id = ?", serviceAccount.ID).First(policy).Error; lookupErr != nil {
		return 0, fmt.Errorf("load service account %q policy: %w", serviceAccount.ID, lookupErr)
	}

	namespaces := make([]string, 0, len(resolved))
	for namespace := range resolved {
		namespaces = append(namespaces, namespace)
	}
	slices.Sort(namespaces)

	for _, namespace := range namespaces {
		grant := &models.ServiceAccountAuthorizationGrant{
			PolicyID:  policy.ID,
			Namespace: namespace,
			Scope:     models.AuthorizationScopePartitionTree,
			BaseModel: data.BaseModel{
				TenantID:    serviceAccount.TenantID,
				PartitionID: serviceAccount.PartitionID,
			},
		}
		if createErr := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(grant).Error; createErr != nil {
			return 0, fmt.Errorf("create policy grant %q/%q: %w", serviceAccount.ID, namespace, createErr)
		}
		grant.ID = ""
		if lookupErr := tx.Where("policy_id = ? AND namespace = ? AND scope = ?", policy.ID, namespace, grant.Scope).
			First(grant).Error; lookupErr != nil {
			return 0, fmt.Errorf("load policy grant %q/%q: %w", serviceAccount.ID, namespace, lookupErr)
		}

		for _, permission := range resolved[namespace] {
			permissionModel := &models.ServiceAccountAuthorizationPermission{
				GrantID:    grant.ID,
				Permission: permission,
				BaseModel: data.BaseModel{
					TenantID:    serviceAccount.TenantID,
					PartitionID: serviceAccount.PartitionID,
				},
			}
			if createErr := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(permissionModel).Error; createErr != nil {
				return 0, fmt.Errorf("create policy permission %q/%q/%q: %w", serviceAccount.ID, namespace, permission, createErr)
			}
		}
	}

	return int64(len(namespaces)), nil
}

func validateMigratedAuthContract(tx *gorm.DB, expected AuthContractMigrationExpectations) error {
	var clientCount int64
	if err := tx.Table("clients").Where("deleted_at IS NULL").Count(&clientCount).Error; err != nil {
		return fmt.Errorf("count migrated clients: %w", err)
	}
	if err := assertExpected("clients", clientCount, expected.Clients); err != nil {
		return err
	}

	var serviceAccountCount int64
	if err := tx.Table("service_accounts").Where("deleted_at IS NULL").Count(&serviceAccountCount).Error; err != nil {
		return fmt.Errorf("count migrated service accounts: %w", err)
	}
	if err := assertExpected("service accounts", serviceAccountCount, expected.ServiceAccounts); err != nil {
		return err
	}

	var policyCount int64
	if err := tx.Model(&models.ServiceAccountAuthorizationPolicy{}).Where("deleted_at IS NULL").Count(&policyCount).Error; err != nil {
		return fmt.Errorf("count migrated authorization policies: %w", err)
	}
	if policyCount != serviceAccountCount {
		return fmt.Errorf("auth contract migration: policies=%d service_accounts=%d", policyCount, serviceAccountCount)
	}

	var orphanRecipients int64
	if err := tx.Table("oauth_client_recipients AS recipients").
		Joins("LEFT JOIN clients ON clients.id = recipients.client_ref AND clients.deleted_at IS NULL").
		Where("recipients.deleted_at IS NULL AND clients.id IS NULL").
		Count(&orphanRecipients).Error; err != nil {
		return fmt.Errorf("count orphan OAuth recipients: %w", err)
	}
	if orphanRecipients != 0 {
		return fmt.Errorf("auth contract migration: found %d orphan OAuth recipients", orphanRecipients)
	}

	return nil
}

func hasColumn(tx *gorm.DB, table, column string) (bool, error) {
	var count int64
	err := tx.Raw(
		"SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?",
		table,
		column,
	).Scan(&count).Error
	if err != nil {
		return false, fmt.Errorf("inspect %s.%s: %w", table, column, err)
	}
	return count == 1, nil
}

func assertExpected(name string, actual, expected int64) error {
	if expected < 0 {
		return nil
	}
	if actual != expected {
		return fmt.Errorf("auth contract migration: expected %s=%d, got %d", strings.TrimSpace(name), expected, actual)
	}
	return nil
}
