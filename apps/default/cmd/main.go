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

package main

import (
	"context"

	"buf.build/gen/go/antinvestor/device/connectrpc/go/device/v1/devicev1connect"
	"buf.build/gen/go/antinvestor/notification/connectrpc/go/notification/v1/notificationv1connect"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v1/tenancyv1connect"
	"github.com/antinvestor/common"
	"github.com/antinvestor/common/connection"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/cache"
	"github.com/pitabwire/frame/cache/jetstreamkv"
	"github.com/pitabwire/frame/cache/valkey"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
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

	rawCache, err := setupCache(ctx, cfg)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not setup cache")
	}

	ctx, svc := frame.NewServiceWithContext(ctx,
		frame.WithConfig(&cfg),
		frame.WithCache(cfg.CacheName, rawCache), frame.WithDatastore())

	log := util.Log(ctx)

	sm := svc.SecurityManager()
	dbManager := svc.DatastoreManager()
	cacheManager := svc.CacheManager()

	workManager := svc.WorkManager()
	dbPool := dbManager.GetPool(ctx, datastore.DefaultPoolName)

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, dbManager, cfg) {
		return
	}

	partitionCli, err := setupPartitionClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup partition service client")
	}

	notificationCli, err := setupNotificationClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup notification service client")
	}

	profileCli, err := setupProfileClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup profile service")
	}

	deviceCli, err := setupDeviceClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup device service")
	}

	serviceTranslations := frame.WithTranslation("/localization", "en", "sw", "lg", "fr", "ar", "es")
	serviceOptions := []frame.Option{serviceTranslations}

	// Initialise service early to get localization manager
	svc.Init(ctx, serviceTranslations)
	localizationMan := svc.LocalizationManager()

	loginRepo := repository.NewLoginRepository(ctx, dbPool, workManager)
	loginEventRepo := repository.NewLoginEventRepository(ctx, dbPool, workManager)

	srv := handlers.NewAuthServer(ctx, sm, &cfg, cacheManager, loginRepo, loginEventRepo, profileCli, deviceCli, partitionCli, notificationCli, localizationMan)

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
			util.Log(ctx).WithError(err).Fatal("database migration failed")
		}
		return true
	}
	return false
}

func setupCache(_ context.Context, cfg aconfig.AuthenticationConfig) (cache.RawCache, error) {
	cacheDSN := data.DSN(cfg.CacheURI)

	cacheOptions := []cache.Option{
		cache.WithDSN(cacheDSN),
	}

	if cfg.CacheCredentialsFile != "" {
		cacheOptions = append(cacheOptions, cache.WithCredsFile(cfg.CacheCredentialsFile))
	}

	if cacheDSN.IsNats() {
		// Setup cache for connection metadata
		return jetstreamkv.New(cacheOptions...)
	} else if cacheDSN.IsRedis() {
		return valkey.New(cacheOptions...)
	} else {
		return cache.NewInMemoryCache(), nil
	}
}

// setupDeviceClient creates and configures the device client.
func setupDeviceClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (devicev1connect.DeviceServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.DeviceServiceURI,
		WorkloadAPITargetPath: cfg.DeviceServiceWorkloadAPITargetPath,
		Audiences:             []string{"service_device"},
	}, devicev1connect.NewDeviceServiceClient)
}

// setupNotificationClient creates and configures the notification client.
func setupNotificationClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (notificationv1connect.NotificationServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.NotificationServiceURI,
		WorkloadAPITargetPath: cfg.NotificationServiceWorkloadAPITargetPath,
		Audiences:             []string{"service_notification"},
	}, notificationv1connect.NewNotificationServiceClient)
}

// setupPartitionClient creates and configures the partition client.
func setupPartitionClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (tenancyv1connect.TenancyServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.TenancyServiceURI,
		WorkloadAPITargetPath: cfg.TenancyServiceWorkloadAPITargetPath,
		Audiences:             []string{"service_tenancy"},
	}, tenancyv1connect.NewTenancyServiceClient)
}

// setupProfileClient creates and configures the profile client.
func setupProfileClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (profilev1connect.ProfileServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.ProfileServiceURI,
		WorkloadAPITargetPath: cfg.ProfileServiceWorkloadAPITargetPath,
		Audiences:             []string{"service_profile"},
	}, profilev1connect.NewProfileServiceClient)
}
