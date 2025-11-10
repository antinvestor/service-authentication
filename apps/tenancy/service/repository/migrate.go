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
		return errors.New("datastore pool is not initialized")
	}

	return dbManager.Migrate(ctx, pool, migrationPath,
		models.Tenant{}, models.Partition{}, models.PartitionRole{},
		models.Access{}, models.AccessRole{}, models.Page{})
}
