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
	"errors"
	"net/http"

	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v1/tenancyv1connect"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/common"
	"github.com/antinvestor/common/connection"
	"github.com/antinvestor/common/permissions"
	aconfig "github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/security/interceptors/connect"
	securityhttp "github.com/pitabwire/frame/security/interceptors/httptor"
	"github.com/pitabwire/util"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadWithOIDC[aconfig.TenancyConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	if cfg.Name() == "" {
		cfg.ServiceName = "service_tenancy"
	}

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithDatastore())

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, &cfg, svc.DatastoreManager()) {
		return
	}

	sm := svc.SecurityManager()

	// Unauthenticated HTTP client for Hydra admin API calls.
	// Hydra admin is cluster-internal and doesn't require OAuth2 tokens.
	// Using the authenticated client causes bootstrap failures when the
	// service's own OAuth2 client isn't yet registered in Hydra.
	hydraClient := client.NewManager(context.Background())

	profileCli, err := connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.ProfileServiceURI,
		WorkloadAPITargetPath: cfg.ProfileServiceWorkloadAPITargetPath,
		Audiences:             []string{"service_profile"},
	}, profilev1connect.NewProfileServiceClient)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not setup profile service client")
	}

	auth := sm.GetAuthorizer(ctx)
	partSrv := handlers.NewTenancyServer(ctx, svc, auth, profileCli)

	// Setup Connect server
	connectHandler := setupConnectServer(ctx, sm, partSrv)

	// Register permission manifest for the tenancy service so the UI can
	// discover available permissions for assignment.
	sd := tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService")

	// Setup HTTP handlers
	serviceOptions := []frame.Option{
		frame.WithHTTPHandler(connectHandler),
		frame.WithPermissionRegistration(sd),
		frame.WithRegisterEvents(
			events.NewPartitionSynchronizationEventHandler(ctx, &cfg, hydraClient, partSrv.PartitionRepo),
			events.NewClientSynchronizationEventHandler(ctx, &cfg, hydraClient, partSrv.ClientRepo, partSrv.ServiceAccountRepo),
			events.NewServiceAccountSynchronizationEventHandler(ctx, &cfg, hydraClient, partSrv.ServiceAccountRepo, partSrv.PartitionRepo),
			events.NewAuthzPartitionSyncEventHandler(partSrv.PartitionRepo, partSrv.ServiceAccountRepo, auth),
			events.NewAuthzServiceAccountSyncEventHandler(partSrv.ServiceAccountRepo, auth),
			events.NewAuthzAccessSyncEventHandler(partSrv.AccessRepo, partSrv.AccessRoleRepo, partSrv.PartitionRoleRepo, partSrv.ServiceNamespaceRepo, auth),
			events.NewTupleWriteEventHandler(auth),
			events.NewTupleDeleteEventHandler(auth),
		),
	}

	svc.Init(ctx, serviceOptions...)

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
			util.Log(ctx).WithError(err).Fatal("database migration failed")
		}
		return true
	}
	return false
}

// setupConnectServer initialises and configures the connect server.
func setupConnectServer(
	ctx context.Context,
	sm security.Manager,
	implementation *handlers.TenancyServer,
) http.Handler {

	authenticator := sm.GetAuthenticator(ctx)
	auth := sm.GetAuthorizer(ctx)
	tenancyAccessChecker := authorizer.NewTenancyAccessChecker(auth, authz.NamespaceTenancyAccess)

	// Connect: tenancy access interceptor runs after authentication to verify data access.
	tenancyAccessInterceptor := connectInterceptors.NewTenancyAccessInterceptor(tenancyAccessChecker)

	// Layer 2: FunctionAccessInterceptor enforces per-RPC permissions from proto annotations.
	sd := tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService")
	procMap := permissions.BuildProcedureMap(sd)
	svcPerms := permissions.ForService(sd)
	functionChecker := authorizer.NewFunctionChecker(auth, svcPerms.Namespace)
	functionAccessInterceptor := connectInterceptors.NewFunctionAccessInterceptor(functionChecker, procMap)

	defaultInterceptorList, err := connectInterceptors.DefaultList(ctx, authenticator, tenancyAccessInterceptor, functionAccessInterceptor)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to create default interceptors")
	}

	_, serverHandler := tenancyv1connect.NewTenancyServiceHandler(
		implementation, connect.WithInterceptors(defaultInterceptorList...))

	// HTTP: auth middleware (outer) populates claims → tenancy access (inner) verifies data access → handler.
	publicRestHandler := securityhttp.AuthenticationMiddleware(
		securityhttp.TenancyAccessMiddleware(implementation.NewSecureRouterV1(), tenancyAccessChecker),
		authenticator)

	mux := http.NewServeMux()
	mux.Handle("/", serverHandler)
	mux.Handle("/public/", http.StripPrefix("/public", publicRestHandler))

	// Internal endpoints — no auth middleware. Safe because they're only
	// reachable within the cluster (not exposed through the API gateway).
	mux.Handle("/_internal/sync/clients", implementation.NewInternalSyncHandler())
	mux.Handle("/_internal/register/permissions", implementation.NewInternalPermissionsHandler())

	return mux
}
