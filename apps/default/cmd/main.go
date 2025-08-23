package main

import (
	"context"

	apis "github.com/antinvestor/apis/go/common"
	devicev1 "github.com/antinvestor/apis/go/device/v1"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	handlers2 "github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/util"
)

func main() {

	ctx := context.Background()
	serviceName := "service_authentication"

	cfg, err := frame.ConfigLoadWithOIDC[config.AuthenticationConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	ctx, svc := frame.NewServiceWithContext(ctx, serviceName, frame.WithConfig(&cfg))
	log := svc.Log(ctx)

	serviceOptions := []frame.Option{frame.WithDatastore()}

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, svc, cfg, log) {
		return
	}

	err = svc.RegisterForJwt(ctx)
	if err != nil {
		log.WithError(err).Fatal("main -- could not register for jwt")
	}

	var profileCli *profilev1.ProfileClient
	var deviceCli *devicev1.DeviceClient
	var partitionCli *partitionv1.PartitionClient

	partitionCli, err = partitionv1.NewPartitionsClient(ctx,
		apis.WithEndpoint(cfg.PartitionServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstInternalSystemScope),
		apis.WithAudiences("service_partition"))
	if err != nil {
		log.WithError(err).Fatal("could not setup partition service client: %v", err)
	}

	profileCli, err = profilev1.NewProfileClient(ctx,
		apis.WithEndpoint(cfg.ProfileServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstInternalSystemScope),
		apis.WithAudiences("service_profile"))
	if err != nil {
		log.WithError(err).Fatal("could not setup profile service : %v", err)
	}

	deviceCli, err = devicev1.NewDeviceClient(ctx,
		apis.WithEndpoint(cfg.DeviceServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstInternalSystemScope),
		apis.WithAudiences("service_devices"))
	if err != nil {
		log.WithError(err).Fatal("could not setup devices service : %v", err)
	}

	serviceTranslations := frame.WithTranslations("/localization", "en")
	serviceOptions = append(serviceOptions, serviceTranslations)

	srv := handlers2.NewAuthServer(ctx, svc, &cfg, profileCli, deviceCli, partitionCli, nil)

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
	cfg config.AuthenticationConfig,
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
