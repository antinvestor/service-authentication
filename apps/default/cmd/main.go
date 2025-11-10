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
	handlers2 "github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/config"
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

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithRegisterServerOauth2Client())
	log := svc.Log(ctx)

	serviceOptions := []frame.Option{frame.WithDatastore()}

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, svc, cfg, log) {
		return
	}

	partitionCli, err := setupPartitionClient(ctx, svc.SecurityManager(), cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup partition service client: %v", err)
	}

	notificationCli, err := setupNotificationClient(ctx, svc.SecurityManager(), cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup notification service client: %v", err)
	}

	profileCli, err := setupProfileClient(ctx, svc.SecurityManager(), cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup profile service : %v", err)
	}

	deviceCli, err := setupDeviceClient(ctx, svc.SecurityManager(), cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup devices service : %v", err)
	}

	serviceTranslations := frame.WithTranslation("/localization", "en")
	serviceOptions = append(serviceOptions, serviceTranslations)

	srv := handlers2.NewAuthServer(ctx, svc, &cfg, profileCli, deviceCli, partitionCli, notificationCli)

	defaultServer := frame.WithHTTPHandler(srv.SetupRouterV1(ctx))
	serviceOptions = append(serviceOptions, defaultServer)

	svc.Init(ctx, serviceOptions...)

	log.WithField("server http port", cfg.HTTPPort()).
		WithField("server grpc port", cfg.GrpcPort()).
		Info(" Initiating server operations")
	err = svc.Run(ctx, "")
	if err != nil {
		log.WithError(err).Error("could not run service")
	}
}

// handleDatabaseMigration performs database migration if configured to do so.
func handleDatabaseMigration(
	ctx context.Context,
	svc *frame.Service,
	cfg aconfig.AuthenticationConfig,
	log *util.LogEntry,
) bool {
	serviceOptions := []frame.Option{frame.WithDatastore()}

	if cfg.DoDatabaseMigrate() {
		svc.Init(ctx, serviceOptions...)

		err := repository.Migrate(ctx, svc, cfg.GetDatabaseMigrationPath())
		if err != nil {
			log.WithError(err).Fatal("main -- Could not migrate successfully")
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
		common.WithAudiences("service_partition"))
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
