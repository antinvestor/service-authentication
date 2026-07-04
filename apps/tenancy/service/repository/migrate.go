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

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore"
)

type legacyClientMigrationModel struct {
	models.Client
	Audiences data.JSONMap
	Roles     data.JSONMap
}

func (*legacyClientMigrationModel) TableName() string { return "clients" }

type legacyServiceAccountMigrationModel struct {
	models.ServiceAccount
	Audiences    data.JSONMap
	ClientSecret string `gorm:"type:varchar(250);"`
}

func (*legacyServiceAccountMigrationModel) TableName() string { return "service_accounts" }

func Migrate(
	ctx context.Context,
	dbManager datastore.Manager,
	migrationPath string,
	audienceBaseURL string,
	expected AuthContractMigrationExpectations,
) error {

	pool := dbManager.GetPool(ctx, datastore.DefaultMigrationPoolName)
	if pool == nil {
		return errors.New("datastore pool is not initialised")
	}

	// Models must be passed as pointers: tenancy enrollment checks for the
	// tenancy.Tenanted interface whose methods have pointer receivers, so
	// value models silently skip RLS policy installation.
	db := pool.DB(ctx, false)
	if db == nil {
		return errors.New("writable datastore is not configured")
	}
	clientModel := any(&models.Client{})
	if !db.Migrator().HasTable(&models.Client{}) {
		clientModel = &legacyClientMigrationModel{}
	}
	serviceAccountModel := any(&models.ServiceAccount{})
	if !db.Migrator().HasTable(&models.ServiceAccount{}) {
		serviceAccountModel = &legacyServiceAccountMigrationModel{}
	}

	migrationModels := []any{
		&models.Tenant{}, &models.Partition{}, &models.PartitionRole{},
		&models.Access{}, &models.AccessRole{}, &models.Page{},
		clientModel, serviceAccountModel, &models.ServiceNamespace{},
		&models.OAuthClientRecipient{},
		&models.ServiceAccountAuthorizationPolicy{},
		&models.ServiceAccountAuthorizationGrant{},
		&models.ServiceAccountAuthorizationPermission{},
		&models.ServiceAccountAppliedTuple{},
	}

	// A fresh database must replay historical SQL against the schema those
	// migrations were written for. Add the four legacy columns only while
	// bootstrapping; MigrateAuthContractV2 backfills and drops them before the
	// application starts. Existing v2 databases must never recreate them.
	err := dbManager.Migrate(ctx, pool, migrationPath, migrationModels...)
	if err != nil {
		return err
	}

	return MigrateAuthContractV2(ctx, pool, audienceBaseURL, expected)
}
