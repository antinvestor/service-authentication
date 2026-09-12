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

	"buf.build/gen/go/antinvestor/audit/connectrpc/go/audit/v1/auditv1connect"
	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/common/v2/permissions"
	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/handlers"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/v2/security/interceptors/connect"
	"github.com/pitabwire/frame/v2/setup"
	"github.com/pitabwire/util"
)

const namespaceAudit = "service_audit"
const namespaceTenancyAccess = "tenancy_access"

func main() {
	ctx := context.Background()

	cfg, err := config.LoadWithOIDC[aconfig.AuditConfig](ctx)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("could not process configs")
		return
	}
	if cfg.Name() == "" {
		cfg.ServiceName = namespaceAudit
	}

	ctx, svc := frame.NewServiceWithContext(ctx,
		frame.WithConfig(&cfg),
		frame.WithDatastore(),
		frame.WithSystemPrincipalAllowGlobal(namespaceAudit),
	)

	sd := auditv1.File_audit_v1_audit_proto.Services().ByName("AuditService")

	// Setup plan: migrate → seed signing key → permissions. No runtime PreStart.
	svc.Setup().RegisterFunc(setup.NameMigrate, func(ctx context.Context) error {
		if mErr := repository.Migrate(ctx, svc.DatastoreManager(), cfg.GetDatabaseMigrationPath()); mErr != nil {
			return mErr
		}
		return seedSigningKey(ctx, svc, &cfg)
	})

	if frame.ShouldRunSetup(&cfg) {
		svc.Init(ctx, frame.WithPermissionRegistration(sd))
		if setupErr := svc.RunSetupForProcess(ctx, &cfg); setupErr != nil {
			util.Log(ctx).WithError(setupErr).Fatal("setup plan failed")
		}
		util.Log(ctx).Info("setup plan complete — exiting")
		return
	}

	// Runtime: the process refuses to start without a usable signing key.
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	keys, err := business.NewKeyProvider(ctx, &cfg, repository.NewSigningKeyRepository(ctx, dbPool))
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("audit signing key is not usable")
		return
	}
	if _, err = keys.Active(); err != nil {
		util.Log(ctx).WithError(err).Fatal("audit signing key is not usable")
		return
	}

	deps := handlers.BuildDeps(ctx, &cfg, namespaceAudit, dbPool, keys)
	mux := setupConnectServer(ctx, svc.SecurityManager(), deps)

	svc.AddHealthCheck(deps.Writer.ReadinessChecker())
	svc.AddLivenessCheck(deps.Writer.LivenessChecker())

	svc.Init(ctx,
		frame.WithHTTPHandler(mux),
		frame.WithBackgroundConsumer(deps.Writer.Run),
	)

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

// seedSigningKey registers the configured key's public half when absent.
func seedSigningKey(ctx context.Context, svc *frame.Service, cfg *aconfig.AuditConfig) error {
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultMigrationPoolName)
	keys, err := business.NewKeyProvider(ctx, cfg, repository.NewSigningKeyRepository(ctx, dbPool))
	if err != nil {
		return err
	}
	return keys.Seed(ctx)
}

// setupConnectServer builds the Connect handler with the interceptor chain
// Auth → TenancyAccess → FunctionAccess, plus the unauthenticated
// well-known keys document outside the Connect handler.
func setupConnectServer(ctx context.Context, sm security.Manager, deps *handlers.Deps) http.Handler {
	authenticator := sm.GetAuthenticator(ctx)
	auth := sm.GetAuthorizer(ctx)

	tenancyAccessChecker := authorizer.NewTenancyAccessChecker(auth, namespaceTenancyAccess)
	tenancyAccessInterceptor := connectInterceptors.NewTenancyAccessInterceptor(tenancyAccessChecker)

	sd := auditv1.File_audit_v1_audit_proto.Services().ByName("AuditService")
	procMap := permissions.BuildProcedureMap(sd)
	svcPerms := permissions.ForService(sd)
	functionChecker := authorizer.NewFunctionChecker(auth, svcPerms.Namespace)
	functionAccessInterceptor := connectInterceptors.NewFunctionAccessInterceptor(functionChecker, procMap)

	interceptors, err := connectInterceptors.DefaultList(ctx, authenticator, tenancyAccessInterceptor, functionAccessInterceptor)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to create default interceptors")
	}

	implementation := handlers.NewAuditServer(deps, functionChecker)
	_, serverHandler := auditv1connect.NewAuditServiceHandler(implementation, connect.WithInterceptors(interceptors...))

	mux := http.NewServeMux()
	mux.Handle(handlers.WellKnownKeysPath, handlers.WellKnownKeysHandler(deps.Keys, namespaceAudit))
	mux.Handle("/", serverHandler)
	return mux
}
