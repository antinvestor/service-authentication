package main

import (
	"context"

	"buf.build/gen/go/antinvestor/device/connectrpc/go/device/v1/devicev1connect"
	"buf.build/gen/go/antinvestor/notification/connectrpc/go/notification/v1/notificationv1connect"
	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"github.com/antinvestor/apis/go/common"
	"github.com/antinvestor/apis/go/device"
	"github.com/antinvestor/apis/go/notification"
	"github.com/antinvestor/apis/go/partition"
	"github.com/antinvestor/apis/go/profile"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/openid"
	"github.com/pitabwire/util"
)

func main() {

	ctx := context.Background()

	cfg, err := config.LoadWithOIDC[aconfig.AuthenticationConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	if cfg.Name() == "" {
		cfg.ServiceName = "service_authentication"
	}

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithRegisterServerOauth2Client(), frame.WithDatastore())

	log := svc.Log(ctx)

	sm := svc.SecurityManager()
	dbManager := svc.DatastoreManager()

	workManager := svc.WorkManager()
	dbPool := dbManager.GetPool(ctx, datastore.DefaultPoolName)

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, dbManager, cfg) {
		return
	}

	partitionCli, err := setupPartitionClient(ctx, sm, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup partition service client: %v", err)
	}

	notificationCli, err := setupNotificationClient(ctx, sm, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup notification service client: %v", err)
	}

	profileCli, err := setupProfileClient(ctx, sm, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup profile service : %v", err)
	}

	deviceCli, err := setupDeviceClient(ctx, sm, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup devices service : %v", err)
	}

	serviceTranslations := frame.WithTranslation("/localization", "en")
	serviceOptions := []frame.Option{serviceTranslations}

	loginRepo := repository.NewLoginRepository(ctx, dbPool, workManager)
	loginEventRepo := repository.NewLoginEventRepository(ctx, dbPool, workManager)
	apiKeyRepo := repository.NewAPIKeyRepository(ctx, dbPool, workManager)

	srv := handlers.NewAuthServer(ctx, svc, &cfg, loginRepo, loginEventRepo, apiKeyRepo, profileCli, deviceCli, partitionCli, notificationCli)

	defaultServer := frame.WithHTTPHandler(srv.SetupRouterV1(ctx))
	serviceOptions = append(serviceOptions, defaultServer)

	svc.Init(ctx, serviceOptions...)

	err = svc.Run(ctx, "")
	if err != nil {
		log.WithError(err).Error("could not run service")
	}
}

// handleDatabaseMigration performs database migration if configured to do so.
func handleDatabaseMigration(
	ctx context.Context,
	dbManager datastore.Manager,
	cfg aconfig.AuthenticationConfig,
) bool {

	if cfg.DoDatabaseMigrate() {

		err := repository.Migrate(ctx, dbManager, cfg.GetDatabaseMigrationPath())
		if err != nil {
			util.Log(ctx).WithError(err).Fatal("main -- Could not migrate successfully")
		}
		return true
	}
	return false
}

// setupDeviceClient creates and configures the device client.
func setupDeviceClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg aconfig.AuthenticationConfig) (devicev1connect.DeviceServiceClient, error) {
	return device.NewClient(ctx,
		common.WithEndpoint(cfg.DeviceServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_devices"))
}

// setupNotificationClient creates and configures the notification client.
func setupNotificationClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg aconfig.AuthenticationConfig) (notificationv1connect.NotificationServiceClient, error) {
	return notification.NewClient(ctx,
		common.WithEndpoint(cfg.NotificationServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_notifications"))
}

// setupPartitionClient creates and configures the partition client.
func setupPartitionClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg aconfig.AuthenticationConfig) (partitionv1connect.PartitionServiceClient, error) {
	return partition.NewClient(ctx,
		common.WithEndpoint(cfg.PartitionServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_tenancy"))
}

// setupProfileClient creates and configures the profile client.
func setupProfileClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg aconfig.AuthenticationConfig) (profilev1connect.ProfileServiceClient, error) {
	return profile.NewClient(ctx,
		common.WithEndpoint(cfg.ProfileServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_profile"))
}
