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

	"github.com/antinvestor/common/v2/servicecatalog"

	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v1/tenancyv1connect"
	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/tenancy/v2/tenancyv2connect"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"connectrpc.com/connect"
	"github.com/antinvestor/common/v2"
	"github.com/antinvestor/common/v2/connection"
	"github.com/antinvestor/common/v2/permissions"
	aconfig "github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/client"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/v2/security/interceptors/connect"
	securityhttp "github.com/pitabwire/frame/v2/security/interceptors/httptor"
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

	isMigration := cfg.DoDatabaseMigrate()

	// Handle database migration if requested
	if isMigration {
		if migErr := repository.Migrate(
			ctx,
			svc.DatastoreManager(),
			cfg.GetDatabaseMigrationPath(),
		); migErr != nil {
			util.Log(ctx).WithError(migErr).Fatal("database migration failed")
		}
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
		ServiceID:             servicecatalog.ServiceProfile,
	}, profilev1connect.NewProfileServiceClient)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not setup profile service client")
	}

	auth := sm.GetAuthorizer(ctx)
	partSrv := handlers.NewTenancyServer(ctx, svc, profileCli)
	authContractSrv, err := handlers.NewAuthContractServer(partSrv, cfg.GetOauth2AudienceBaseURL())
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not setup tenancy v2 auth contract service")
	}
	policySync := events.NewAuthzServiceAccountSyncEventHandler(
		partSrv.ServiceAccountRepo,
		partSrv.PartitionRepo,
		partSrv.AuthorizationPolicyRepo,
		partSrv.ServiceNamespaceRepo,
		partSrv.AuthContractRepo,
		svc.EventsManager(),
		auth,
	)

	// Bootstrap root super-user authorization after migration only.
	// This writes Keto tuples for migration-seeded root owners/admins.
	if isMigration {
		if bootstrapErr := business.EnsureRootAuthorization(ctx, business.RootAuthorizationDeps{
			AccessRepo:           partSrv.AccessRepo,
			AccessRoleRepo:       partSrv.AccessRoleRepo,
			PartitionRoleRepo:    partSrv.PartitionRoleRepo,
			ServiceNamespaceRepo: partSrv.ServiceNamespaceRepo,
			Authorizer:           auth,
		}); bootstrapErr != nil {
			util.Log(ctx).WithError(bootstrapErr).Fatal("root authorization bootstrap failed")
		}
	}

	// Service-bot Plane-1 access must self-heal. Under a large SA backlog this
	// (and ReconcilePending) can take minutes, so:
	//  - migration jobs: bot bootstrap only (fatal), no full SA reconcile
	//  - regular pods: both run in the background after HTTP is ready
	runServiceBotBootstrap := func(bootstrapCtx context.Context, fatal bool) {
		if botErr := business.EnsureServiceBotTenancyAccess(bootstrapCtx, business.ServiceBotTenancyDeps{
			ServiceAccountRepo: partSrv.ServiceAccountRepo,
			PartitionRepo:      partSrv.PartitionRepo,
			Authorizer:         auth,
		}); botErr != nil {
			if fatal {
				util.Log(bootstrapCtx).WithError(botErr).Fatal("service bot tenancy access bootstrap failed")
			}
			util.Log(bootstrapCtx).WithError(botErr).Error("service bot tenancy access bootstrap failed; will retry on next restart")
		}
	}

	if isMigration {
		// Do not run ReconcilePending here: it can exceed Helm job timeouts and
		// leave the release Failed while runtime pods already handle the backlog.
		runServiceBotBootstrap(ctx, true)
		util.Log(ctx).Info("migration and root authorization bootstrap complete — exiting")
		return
	}

	// Setup Connect server
	connectHandler := setupConnectServer(ctx, sm, partSrv, authContractSrv)

	// Register permission manifest for the tenancy service so the UI can
	// discover available permissions for assignment.
	sd := tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService")

	// Setup HTTP handlers
	serviceOptions := []frame.Option{
		frame.WithHTTPHandler(connectHandler),
		frame.WithPermissionRegistration(sd),
		frame.WithRegisterEvents(
			events.NewClientSynchronizationEventHandler(
				ctx,
				&cfg,
				hydraClient,
				partSrv.ClientRepo,
				partSrv.OAuthRecipientRepo,
				partSrv.ServiceAccountRepo,
			),
			events.NewAuthzPartitionSyncEventHandler(
				partSrv.PartitionRepo,
				partSrv.ServiceAccountRepo,
				partSrv.ServiceNamespaceRepo,
				partSrv.AuthorizationPolicyRepo,
				svc.EventsManager(),
				auth,
			),
			policySync,
			events.NewAuthzAccessSyncEventHandler(partSrv.AccessRepo, partSrv.AccessRoleRepo, partSrv.PartitionRoleRepo, partSrv.ServiceNamespaceRepo, auth),
			events.NewTupleWriteEventHandler(auth),
			events.NewTupleDeleteEventHandler(auth),
		),
	}

	svc.Init(ctx, serviceOptions...)

	// Heavy authz self-heal after Init so event workers exist, but off the
	// request path so readiness/liveness can succeed immediately.
	go func() {
		bootstrapCtx := context.WithoutCancel(ctx)
		runServiceBotBootstrap(bootstrapCtx, false)
		if reconcileErr := policySync.ReconcilePending(bootstrapCtx); reconcileErr != nil {
			util.Log(bootstrapCtx).WithError(reconcileErr).Error(
				"authorization policy startup reconciliation failed; queue consumers will continue retrying",
			)
		}
	}()

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

// setupConnectServer initialises and configures the connect server.
func setupConnectServer(
	ctx context.Context,
	sm security.Manager,
	implementation *handlers.TenancyServer,
	authContractImplementation *handlers.AuthContractServer,
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

	defaultInterceptorList, err := connectInterceptors.DefaultList(ctx, authenticator,
		tenancyAccessInterceptor, functionAccessInterceptor)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to create default interceptors")
	}

	_, serverHandler := tenancyv1connect.NewTenancyServiceHandler(
		implementation, connect.WithInterceptors(defaultInterceptorList...))

	v2ServiceDescriptor := tenancyv2.File_tenancy_v2_auth_contract_proto.Services().ByName("AuthContractService")
	v2ProcedureMap := permissions.BuildProcedureMap(v2ServiceDescriptor)
	v2ServicePermissions := permissions.ForService(v2ServiceDescriptor)
	v2FunctionChecker := authorizer.NewFunctionChecker(auth, v2ServicePermissions.Namespace)
	v2FunctionInterceptor := connectInterceptors.NewFunctionAccessInterceptor(v2FunctionChecker, v2ProcedureMap)
	v2Interceptors, err := connectInterceptors.DefaultList(
		ctx,
		authenticator,
		tenancyAccessInterceptor,
		v2FunctionInterceptor,
	)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to create tenancy v2 interceptors")
	}
	v2Path, v2Handler := tenancyv2connect.NewAuthContractServiceHandler(
		authContractImplementation,
		connect.WithInterceptors(v2Interceptors...),
	)

	// HTTP: auth middleware (outer) populates claims → tenancy access (inner) verifies data access → handler.
	publicRestHandler := securityhttp.AuthenticationMiddleware(
		securityhttp.TenancyAccessMiddleware(implementation.NewSecureRouterV1(), tenancyAccessChecker),
		authenticator)

	mux := http.NewServeMux()
	mux.Handle(v2Path, v2Handler)
	mux.Handle("/", serverHandler)
	mux.Handle("/public/", http.StripPrefix("/public", publicRestHandler))

	// Client bootstrap remains cluster-internal. Permission registration also
	// requires a verified service-account token and binds namespaces to it.
	mux.Handle("/_internal/sync/clients", implementation.NewInternalSyncHandler())
	mux.Handle(
		"/_internal/register/permissions",
		securityhttp.AuthenticationMiddleware(implementation.NewPermissionRegistrationHandler(), authenticator),
	)

	return mux
}
