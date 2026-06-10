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
	"github.com/pitabwire/frame/datastore"
)

func Migrate(ctx context.Context, dbManager datastore.Manager, migrationPath string) error {

	pool := dbManager.GetPool(ctx, datastore.DefaultMigrationPoolName)
	if pool == nil {
		return errors.New("datastore pool is not initialised")
	}

	// Models must be passed as pointers: tenancy enrollment checks for the
	// tenancy.Tenanted interface whose methods have pointer receivers, so
	// value models silently skip RLS policy installation.
	return dbManager.Migrate(ctx, pool, migrationPath,
		&models.Tenant{}, &models.Partition{}, &models.PartitionRole{},
		&models.Access{}, &models.AccessRole{}, &models.Page{},
		&models.Client{}, &models.ServiceAccount{}, &models.ServiceNamespace{})
}
