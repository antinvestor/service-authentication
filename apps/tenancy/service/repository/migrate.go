package repository

import (
	"context"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"

	"github.com/pitabwire/frame"
)

func Migrate(ctx context.Context, svc *frame.Service, migrationPath string) error {
	return svc.MigrateDatastore(ctx, migrationPath,
		models.Tenant{}, models.Partition{}, models.PartitionRole{},
		models.Access{}, models.AccessRole{}, models.Page{})
}
