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
	"fmt"
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
	"github.com/antinvestor/service-authentication/pkg/hydraadmin"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/v2/security/interceptors/connect"
	securityhttp "github.com/pitabwire/frame/v2/security/interceptors/httptor"
	"github.com/pitabwire/frame/v2/setup"
	"github.com/pitabwire/util"
)

func main() {
	ctx := context.Background()

	// Migration/setup jobs must not depend on OIDC discovery or peer service
	// clients (profile requires a token endpoint). Load env-only first; full
	// OIDC is loaded below for the runtime path.
	cfg, err := config.FromEnv[aconfig.TenancyConfig]()
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}

	if cfg.Name() == "" {
		cfg.ServiceName = "service_tenancy"
	}

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithDatastore())
	sm := svc.SecurityManager()
	// Tuple mutations must be serialised across every tenancy process — Keto
	// has no uniqueness constraint and Frame's read-then-insert WriteTuples
	// duplicates tuples under concurrent writers. See authz.SerialisedAuthorizer.
	auth := authz.SerialisedAuthorizer(ctx, svc)

	// Setup plan (migrate + bootstrap) must run without profile/Hydra clients.
	// NewTenancyServer accepts a nil profile client for repo/bootstrap wiring.
	setupPartSrv := handlers.NewTenancyServer(ctx, svc, nil)
	svc.Setup().RegisterFunc(setup.NameMigrate, func(ctx context.Context) error {
		return repository.Migrate(ctx, svc.DatastoreManager(), cfg.GetDatabaseMigrationPath())
	})
	// Setup Job only (migrate → bootstrap → …). Never on runtime cold start.
	// Bootstrap: root tuples, service-bot Plane-1 access, then materialise any
	// SA authorization policies whose namespaces are already registered.
	svc.Setup().RegisterFunc(setup.NameBootstrap, func(ctx context.Context) error {
		if bootstrapErr := business.EnsureRootAuthorization(ctx, business.RootAuthorizationDeps{
			AccessRepo:           setupPartSrv.AccessRepo,
			AccessRoleRepo:       setupPartSrv.AccessRoleRepo,
			PartitionRoleRepo:    setupPartSrv.PartitionRoleRepo,
			ServiceNamespaceRepo: setupPartSrv.ServiceNamespaceRepo,
			Authorizer:           auth,
		}); bootstrapErr != nil {
			return bootstrapErr
		}
		if botErr := business.EnsureServiceBotTenancyAccess(ctx, business.ServiceBotTenancyDeps{
			ServiceAccountRepo: setupPartSrv.ServiceAccountRepo,
			PartitionRepo:      setupPartSrv.PartitionRepo,
			Authorizer:         auth,
		}); botErr != nil {
			return botErr
		}
		// Materialise pending SA policies (Plane-2 granted_*) for namespaces that
		// are already registered. Policies whose namespaces are still missing stay
		// pending until files/profile/etc. setup Jobs re-register and requeue them.
		reconciler := events.NewAuthzServiceAccountSyncEventHandler(
			setupPartSrv.ServiceAccountRepo,
			setupPartSrv.PartitionRepo,
			setupPartSrv.AuthorizationPolicyRepo,
			setupPartSrv.ServiceNamespaceRepo,
			setupPartSrv.AuthContractRepo,
			svc.EventsManager(),
			auth,
		)
		if recErr := reconciler.ReconcilePending(ctx); recErr != nil {
			return fmt.Errorf("setup bootstrap: reconcile pending SA policies: %w", recErr)
		}
		return nil
	})

	if frame.ShouldRunSetup(&cfg) {
		// Tenancy is the permission registration *target* — skip self-registration
		// unless PERMISSIONS_REGISTRATION_URL is explicitly set to another host.
		svc.Init(ctx)
		if setupErr := svc.RunSetupForProcess(ctx, &cfg); setupErr != nil {
			util.Log(ctx).WithError(setupErr).Fatal("setup plan failed")
		}
		util.Log(ctx).Info("setup plan complete — exiting")
		return
	}

	if err = cfg.LoadOauth2Config(ctx); err != nil {
		util.Log(ctx).WithError(err).Fatal("could not load oauth2/oidc config")
		return
	}

	// Hydra admin: no service OAuth2 (bootstrap circularity). On Cloud Run the
	// admin surface is IAM-authenticated HTTPS — hydraadmin attaches a Google
	// ID token for roles/run.invoker. Cluster http:// URIs stay plain.
	hydraClient := hydraadmin.NewManager(ctx, cfg.GetOauth2ServiceAdminURI())

	profileCli, err := connection.NewServiceClient(ctx, &cfg, common.ServiceTarget{
		Endpoint:              cfg.ProfileServiceURI,
		WorkloadAPITargetPath: cfg.ProfileServiceWorkloadAPITargetPath,
		ServiceID:             servicecatalog.ServiceProfile,
	}, profilev1connect.NewProfileServiceClient)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not setup profile service client")
	}

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

	// Runtime: fast start — no setup steps, no permission registration.
	connectHandler := setupConnectServer(ctx, sm, partSrv, authContractSrv)
	serviceOptions := []frame.Option{
		frame.WithHTTPHandler(connectHandler),
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

	// Runtime: serve traffic only. Bot bootstrap + SA policy reconcile run in the
	// setup Job (NameBootstrap), not on every cold start.
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

	tenancyAccessInterceptor := connectInterceptors.NewTenancyAccessInterceptor(tenancyAccessChecker)

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

	publicRestHandler := securityhttp.AuthenticationMiddleware(
		securityhttp.TenancyAccessMiddleware(implementation.NewSecureRouterV1(), tenancyAccessChecker),
		authenticator)

	mux := http.NewServeMux()
	mux.Handle(v2Path, v2Handler)
	mux.Handle("/", serverHandler)
	mux.Handle("/public/", http.StripPrefix("/public", publicRestHandler))

	mux.Handle("/_internal/sync/clients", implementation.NewInternalSyncHandler())
	mux.Handle(
		"/_internal/register/permissions",
		securityhttp.AuthenticationMiddleware(implementation.NewPermissionRegistrationHandler(), authenticator),
	)

	return mux
}
