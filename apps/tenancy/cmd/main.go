package main

import (
	"context"
	"errors"
	"net/http"

	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	"connectrpc.com/connect"
	aconfig "github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/security/interceptors/connect"
	securityhttp "github.com/pitabwire/frame/security/interceptors/httptor"
	"github.com/pitabwire/util"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadWithOIDC[aconfig.PartitionConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	if cfg.Name() == "" {
		cfg.ServiceName = "service_tenancy"
	}

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithDatastore(), frame.WithRegisterServerOauth2Client())

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, &cfg, svc.DatastoreManager()) {
		return
	}

	sm := svc.SecurityManager()
	cliMan := svc.HTTPClientManager()

	auth := sm.GetAuthorizer(ctx)
	authzMiddleware := authz.NewMiddleware(auth)
	partSrv := handlers.NewPartitionServer(ctx, svc, authzMiddleware, auth)

	// Setup Connect server
	connectHandler := setupConnectServer(ctx, sm, partSrv)

	// Setup HTTP handlers
	// Start with datastore option
	serviceOptions := []frame.Option{
		frame.WithHTTPHandler(connectHandler),
		frame.WithRegisterEvents(
			events.NewPartitionSynchronizationEventHandler(ctx, &cfg, cliMan, partSrv.PartitionRepo),
			events.NewClientSynchronizationEventHandler(ctx, &cfg, cliMan, partSrv.ClientRepo, partSrv.ServiceAccountRepo),
			events.NewServiceAccountSynchronizationEventHandler(ctx, &cfg, cliMan, partSrv.ServiceAccountRepo, partSrv.PartitionRepo),
			events.NewAuthzPartitionSyncEventHandler(partSrv.PartitionRepo, auth),
			events.NewAuthzServiceAccountSyncEventHandler(partSrv.ServiceAccountRepo, auth),
			events.NewTupleWriteEventHandler(auth),
			events.NewTupleDeleteEventHandler(auth),
		),
	}

	svc.Init(ctx, serviceOptions...)

	// Sync all SA-type clients to Hydra at startup so their metadata
	// (tenant_id, partition_id, profile_id, type) is available for the
	// token enrichment webhook before any service acquires tokens.
	if cfg.SynchronizeClients {
		syncAllClientsToHydra(ctx, &cfg, cliMan, partSrv)
	}

	err = svc.Run(ctx, "")
	if err != nil {
		log := util.Log(ctx).WithError(err)

		if errors.Is(err, context.Canceled) {
			log.Error("server stopping")
		} else {
			log.Fatal("server stopping with error")
		}
	}
}

// handleDatabaseMigration performs database migration if configured to do so.
func handleDatabaseMigration(
	ctx context.Context,
	cfg config.ConfigurationDatabase,
	dbManager datastore.Manager,
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

// syncAllClientsToHydra synchronously syncs unsynced Client records to Hydra.
// This ensures SA metadata is available in the Hydra client metadata field
// before any service attempts to acquire tokens via client_credentials.
// Only clients with NULL synced_at are processed; successfully synced clients
// are marked with a timestamp and skipped on subsequent runs.
func syncAllClientsToHydra(ctx context.Context, cfg *aconfig.PartitionConfig, cliMan client.Manager, partSrv *handlers.PartitionServer) {
	log := util.Log(ctx)
	syncCtx := security.SkipTenancyChecksOnClaims(ctx)

	query := data.NewSearchQuery(
		data.WithSearchLimit(200),
		data.WithSearchFiltersAndByValue(map[string]any{"synced_at IS NULL": ""}),
	)

	jobResult, err := partSrv.ClientRepo.Search(syncCtx, query)
	if err != nil {
		log.WithError(err).Error("failed to search unsynced clients for Hydra sync")
		return
	}

	synced := 0
	for {
		result, ok := jobResult.ReadResult(syncCtx)
		if !ok {
			break
		}
		if result.IsError() {
			log.WithError(result.Error()).Error("error reading unsynced clients for Hydra sync")
			break
		}
		for _, cl := range result.Item() {
			profileID := ""
			if cl.Type == "internal" || cl.Type == "external" {
				sa, saErr := partSrv.ServiceAccountRepo.GetByClientRef(syncCtx, cl.GetID())
				if saErr == nil && sa != nil {
					profileID = sa.ProfileID
				}
			}
			if syncErr := events.SyncClientOnHydra(syncCtx, cfg, cliMan, partSrv.ClientRepo, cl, profileID); syncErr != nil {
				log.WithError(syncErr).WithField("client_id", cl.ClientID).Error("failed to sync client to Hydra")
			} else {
				synced++
				log.WithField("client_id", cl.ClientID).Info("synced client to Hydra at startup")
			}
		}
	}

	log.WithField("count", synced).Info("completed Hydra client startup sync")
}

// setupConnectServer initialises and configures the connect server.
func setupConnectServer(
	ctx context.Context,
	sm security.Manager,
	implementation *handlers.PartitionServer,
) http.Handler {

	authenticator := sm.GetAuthenticator(ctx)
	tenancyAccessChecker := authorizer.NewTenancyAccessChecker(sm.GetAuthorizer(ctx), authz.NamespaceTenancyAccess)

	// Connect: tenancy access interceptor runs after authentication to verify data access.
	tenancyAccessInterceptor := connectInterceptors.NewTenancyAccessInterceptor(tenancyAccessChecker)

	defaultInterceptorList, err := connectInterceptors.DefaultList(ctx, sm.GetAuthenticator(ctx), tenancyAccessInterceptor)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("main -- Could not create default interceptors")
	}

	_, serverHandler := partitionv1connect.NewPartitionServiceHandler(
		implementation, connect.WithInterceptors(defaultInterceptorList...))

	// HTTP: auth middleware (outer) populates claims → tenancy access (inner) verifies data access → handler.
	publicRestHandler := securityhttp.AuthenticationMiddleware(
		securityhttp.TenancyAccessMiddleware(implementation.NewSecureRouterV1(), tenancyAccessChecker),
		authenticator)

	mux := http.NewServeMux()
	mux.Handle("/", serverHandler)
	mux.Handle("/public/", http.StripPrefix("/public", publicRestHandler))

	return mux
}
