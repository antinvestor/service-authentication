package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
)

func Migrate(ctx context.Context, svc *frame.Service, migrationPath string) error {
	return svc.MigrateDatastore(ctx, migrationPath,
		&models.APIKey{}, &models.Session{}, &models.Login{}, &models.LoginEvent{})
}
