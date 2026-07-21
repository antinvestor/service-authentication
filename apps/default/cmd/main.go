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
	"net/http"
	"os"
	"time"

	"github.com/antinvestor/common/v2/servicecatalog"

	"buf.build/gen/go/antinvestor/authentication/connectrpc/go/authentication/v1/authenticationv1connect"
	authv1 "buf.build/gen/go/antinvestor/authentication/protocolbuffers/go/authentication/v1"
	"buf.build/gen/go/antinvestor/device/connectrpc/go/device/v1/devicev1connect"
	"buf.build/gen/go/antinvestor/files/connectrpc/go/files/v1/filesv1connect"
	"buf.build/gen/go/antinvestor/notification/connectrpc/go/notification/v1/notificationv1connect"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v1/tenancyv1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v2/tenancyv2connect"
	"connectrpc.com/connect"
	"github.com/antinvestor/common/v2"
	"github.com/antinvestor/common/v2/connection"
	"github.com/antinvestor/common/v2/permissions"
	"github.com/antinvestor/common/v2/timescale"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/events"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/loginhistory"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/frame/v2/cache/jetstreamkv"
	"github.com/pitabwire/frame/v2/cache/valkey"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/v2/security/interceptors/connect"
	"github.com/pitabwire/util"
)

func main() {

	ctx := context.Background()

	// Load env first. Migration jobs must not perform OIDC discovery / JWKS
	// fetches (external jwks_uri hangs under NetworkPolicy / edge timeouts).
	// Runtime still loads full OIDC via LoadOauth2Config below.
	cfg, err := config.FromEnv[aconfig.AuthenticationConfig]()
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	if cfg.Name() == "" {
		cfg.ServiceName = "service_authentication"
	}

	// Migration-only path: database only — no cache, no OIDC network.
	// Must finish and exit so Helm pre-upgrade Jobs complete (activeDeadline).
	if cfg.DoDatabaseMigrate() {
		runDatabaseMigrationAndExit(ctx, cfg)
		return
	}

	if err = cfg.LoadOauth2Config(ctx); err != nil {
		util.Log(ctx).WithError(err).Fatal("could not load oauth2/oidc config")
		return
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

	// Register hypertables (no-op WARN if timescaledb extension is absent).
	if tsErr := timescale.Ensure(ctx, dbPool.DB(ctx, false), models.Hypertables); tsErr != nil {
		log.WithError(tsErr).Warn("timescale hypertable setup skipped — will retry after cluster migration")
	}

	partitionCli, err := setupPartitionClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup partition service client")
	}
	authContractCli, err := setupAuthContractClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup tenancy auth contract client")
	}

	notificationCli, err := setupNotificationClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup notification service client")
	}

	profileCli, err := setupProfileClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup profile service")
	}

	filesCli, err := setupFilesClient(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("could not setup files service")
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
	externalIdentityRepo := repository.NewExternalIdentityRepository(ctx, dbPool, workManager)

	srv := handlers.NewAuthServer(ctx, sm, &cfg, cacheManager, loginRepo, loginEventRepo, externalIdentityRepo, profileCli, deviceCli, partitionCli, authContractCli, notificationCli, localizationMan)
	srv.SetEventsManager(svc.EventsManager())

	// Setup Connect RPC handler for login history API
	loginHistorySrv := loginhistory.NewLoginHistoryServer(loginEventRepo, loginRepo)
	connectPath, connectHandler := setupConnectServer(ctx, sm, loginHistorySrv)

	// Combine auth routes and Connect RPC into a single handler.
	// Frame's WithHTTPHandler uses plain assignment (not append), so only
	// the last call wins — both must share one mux.
	authMux := srv.SetupRouterV1(ctx)
	authMux.Handle(connectPath, connectHandler)

	defaultServer := frame.WithHTTPHandler(authMux)
	serviceOptions = append(serviceOptions, defaultServer)

	// Register permission manifest for the authentication service
	sd := authv1.File_authentication_v1_authentication_proto.Services().ByName("AuthenticationService")
	serviceOptions = append(serviceOptions, frame.WithPermissionRegistration(sd))

	// Register async event consumers (queue-backed — scales with replicas).
	serviceOptions = append(serviceOptions, frame.WithRegisterEvents(
		events.NewProfileAvatarSyncEventHandler(profileCli, filesCli),
		events.NewServiceAccountLoginAuditEventHandler(loginRepo, loginEventRepo),
	))

	svc.Init(ctx, serviceOptions...)

	err = svc.Run(ctx, "")
	if err != nil {
		log.WithError(err).Error("could not run service")
	}
}

// migrationBudget is the hard upper bound for Helm pre-upgrade migrate Jobs.
// Frame advisory locks retry until ctx is cancelled; without a deadline a
// stuck lock (or OTLP/NATS side effects during NewService) hangs the Job.
// Allow several minutes so a concurrent lock holder can finish without the
// migrate Job dying mid-wait (seen as "couldn't acquire advisory lock" +
// context deadline exceeded under a 90s cap).
const migrationBudget = 5 * time.Minute

// prepareMigrationEnvironment strips runtime-only deps so Frame bootstrap
// during DO_MIGRATION cannot block on NATS JetStream or OTLP exporters.
// Runtime pods keep full EVENTS_QUEUE_URL / CACHE_URI / OTEL configuration.
func prepareMigrationEnvironment() {
	_ = os.Setenv("EVENTS_QUEUE_URL", "mem://frame.events.migrate")
	_ = os.Setenv("OTEL_TRACES_EXPORTER", "none")
	_ = os.Setenv("OTEL_METRICS_EXPORTER", "none")
	_ = os.Setenv("OTEL_LOGS_EXPORTER", "none")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
	// Avoid secondary pool open during migrate (primary is enough).
	_ = os.Unsetenv("REPLICA_DATABASE_URL")
}

// runDatabaseMigrationAndExit bootstraps the minimum Frame service needed to
// open the primary DB, applies migrations under a hard deadline, then exits
// the process (os.Exit) so residual Frame goroutines cannot keep the Job alive.
func runDatabaseMigrationAndExit(ctx context.Context, cfg aconfig.AuthenticationConfig) {
	log := util.Log(ctx)
	log.Info("migration job starting")

	prepareMigrationEnvironment()

	// Re-parse after env overrides so Frame's internal FromEnv (events/otel)
	// and our cfg stay consistent for the migrate path.
	if refreshed, err := config.FromEnv[aconfig.AuthenticationConfig](); err == nil {
		cfg = refreshed
		if cfg.Name() == "" {
			cfg.ServiceName = "service_authentication"
		}
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, migrationBudget)
	defer cancel()

	log.Info("migration job bootstrapping datastore")
	migrateCtx, svc := frame.NewServiceWithContext(deadlineCtx,
		frame.WithConfig(&cfg),
		frame.WithDatastore())

	if !cfg.DoDatabaseMigrate() {
		svc.Stop(migrateCtx)
		log.Fatal("DO_MIGRATION set but DoDatabaseMigrate is false after env prepare")
		return
	}

	log.Info("migration job applying schema", "path", cfg.GetDatabaseMigrationPath())
	if err := repository.Migrate(migrateCtx, svc.DatastoreManager(), cfg.GetDatabaseMigrationPath()); err != nil {
		svc.Stop(migrateCtx)
		log.WithError(err).Fatal("database migration failed")
		return
	}

	log.Info("database migration finished; exiting")
	// Stop first (releases DB advisory locks), then os.Exit so residual Frame
	// goroutines cannot keep the Helm Job container running.
	svc.Stop(migrateCtx)
	os.Exit(0)
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
		ServiceID:             servicecatalog.ServiceDevices,
	}, devicev1connect.NewDeviceServiceClient)
}

// setupNotificationClient creates and configures the notification client.
func setupNotificationClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (notificationv1connect.NotificationServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.NotificationServiceURI,
		WorkloadAPITargetPath: cfg.NotificationServiceWorkloadAPITargetPath,
		ServiceID:             servicecatalog.ServiceNotification,
	}, notificationv1connect.NewNotificationServiceClient)
}

// setupPartitionClient creates and configures the partition client.
func setupPartitionClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (tenancyv1connect.TenancyServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.TenancyServiceURI,
		WorkloadAPITargetPath: cfg.TenancyServiceWorkloadAPITargetPath,
		ServiceID:             servicecatalog.ServiceTenancy,
	}, tenancyv1connect.NewTenancyServiceClient)
}

func setupAuthContractClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig,
) (tenancyv2connect.AuthContractServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.TenancyServiceURI,
		WorkloadAPITargetPath: cfg.TenancyServiceWorkloadAPITargetPath,
		ServiceID:             servicecatalog.ServiceTenancy,
	}, tenancyv2connect.NewAuthContractServiceClient)
}

// setupProfileClient creates and configures the profile client.
func setupProfileClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (profilev1connect.ProfileServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.ProfileServiceURI,
		WorkloadAPITargetPath: cfg.ProfileServiceWorkloadAPITargetPath,
		ServiceID:             servicecatalog.ServiceProfile,
	}, profilev1connect.NewProfileServiceClient)
}

// setupFilesClient creates and configures the files client used by async
// consumers (e.g. avatar sync) to persist uploads.
func setupFilesClient(
	ctx context.Context,
	cfg aconfig.AuthenticationConfig) (filesv1connect.FilesServiceClient, error) {
	return connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.FilesServiceURI,
		WorkloadAPITargetPath: cfg.FilesServiceWorkloadAPITargetPath,
		ServiceID:             servicecatalog.ServiceFiles,
	}, filesv1connect.NewFilesServiceClient)
}

const namespaceTenancyAccess = "tenancy_access"

// setupConnectServer creates the Connect RPC handler for login history
// with the full interceptor chain: Auth -> TenancyAccess -> FunctionAccess -> TenancyTx.
// Returns the path prefix and handler so they can be registered on the
// shared auth routes mux.
func setupConnectServer(
	ctx context.Context,
	sm security.Manager,
	implementation *loginhistory.LoginHistoryServer,
) (string, http.Handler) {
	authenticator := sm.GetAuthenticator(ctx)
	auth := sm.GetAuthorizer(ctx)

	// Layer 1: TenancyAccess
	tenancyAccessChecker := authorizer.NewTenancyAccessChecker(auth, namespaceTenancyAccess)
	tenancyAccessInterceptor := connectInterceptors.NewTenancyAccessInterceptor(tenancyAccessChecker)

	// Layer 2: FunctionAccess
	sd := authv1.File_authentication_v1_authentication_proto.Services().ByName("AuthenticationService")
	procMap := permissions.BuildProcedureMap(sd)
	svcPerms := permissions.ForService(sd)
	functionChecker := authorizer.NewFunctionChecker(auth, svcPerms.Namespace)
	functionAccessInterceptor := connectInterceptors.NewFunctionAccessInterceptor(functionChecker, procMap)

	defaultInterceptorList, err := connectInterceptors.DefaultList(ctx, authenticator,
		tenancyAccessInterceptor, functionAccessInterceptor)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to create default interceptors for login history")
	}

	return authenticationv1connect.NewAuthenticationServiceHandler(
		implementation, connect.WithInterceptors(defaultInterceptorList...))
}
