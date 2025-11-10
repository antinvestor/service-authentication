package main

import (
	"context"
	"errors"
	"net/http"

	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	aconfig "github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/security"
	securityconnect "github.com/pitabwire/frame/security/interceptors/connect"
	securityhttp "github.com/pitabwire/frame/security/interceptors/http"
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
		cfg.ServiceName = "service_partition"
	}

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithDatastore(), frame.WithRegisterServerOauth2Client())

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, &cfg, svc.DatastoreManager()) {
		return
	}

	sm := svc.SecurityManager()
	cliMan := svc.HTTPClientManager()

	partSrv := handlers.NewPartitionServer(ctx, svc)

	// Setup Connect server
	connectHandler := setupConnectServer(ctx, sm, partSrv)

	// Setup HTTP handlers
	// Start with datastore option
	serviceOptions := []frame.Option{
		frame.WithHTTPHandler(connectHandler),
		frame.WithRegisterEvents(
			events.NewPartitionSynchronizationEventHandler(ctx, &cfg, cliMan, partSrv.PartitionRepo),
		),
	}

	svc.Init(ctx, serviceOptions...)

	log := util.Log(ctx)
	log.WithField("server port", cfg.HTTPPort()).
		Info(" Initiating server operations")
	err = svc.Run(ctx, "")
	if err != nil {
		log = log.WithError(err)

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

// setupConnectServer initialises and configures the connect server.
func setupConnectServer(
	ctx context.Context,
	securityMan security.Manager,
	implementation *handlers.PartitionServer,
) http.Handler {
	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not configure open telemetry")
	}

	validateInterceptor, err := securityconnect.NewValidationInterceptor()
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not configure validation interceptor")
	}

	authenticator := securityMan.GetAuthenticator(ctx)
	authInterceptor := securityconnect.NewAuthInterceptor(authenticator)

	_, serverHandler := partitionv1connect.NewPartitionServiceHandler(
		implementation, connect.WithInterceptors(authInterceptor, otelInterceptor, validateInterceptor))

	publicRestHandler := securityhttp.AuthenticationMiddleware(implementation.NewSecureRouterV1(), authenticator)

	mux := http.NewServeMux()
	mux.Handle("/", serverHandler)
	mux.Handle("/public/", http.StripPrefix("/public", publicRestHandler))

	return mux
}
