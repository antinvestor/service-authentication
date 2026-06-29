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
	"github.com/antinvestor/common/v2/timescale"
	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/handlers"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/security/authorizer"
	connectInterceptors "github.com/pitabwire/frame/v2/security/interceptors/connect"
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

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithConfig(&cfg), frame.WithDatastore())

	// Handle database migration if requested
	if handleDatabaseMigration(ctx, &cfg, svc.DatastoreManager()) {
		return
	}

	// Register hypertables (no-op WARN if timescaledb extension is absent).
	auditDBPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	if tsErr := timescale.Ensure(ctx, auditDBPool.DB(ctx, false), models.Hypertables); tsErr != nil {
		util.Log(ctx).WithError(tsErr).Warn("timescale hypertable setup skipped — will retry after cluster migration")
	}

	// Load or generate the Ed25519 signing key
	signer, err := loadOrGenerateSigner(ctx, cfg.AuditSigningKey)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to initialise audit signing key")
		return
	}

	auditSrv := handlers.NewAuditServer(ctx, svc, signer)

	// Setup Connect RPC server with full interceptor chain
	connectHandler := setupConnectServer(ctx, svc.SecurityManager(), auditSrv)

	// Register permission manifest for the audit service
	sd := auditv1.File_audit_v1_audit_proto.Services().ByName("AuditService")

	serviceOptions := []frame.Option{
		frame.WithHTTPHandler(connectHandler),
		frame.WithPermissionRegistration(sd),
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

// loadOrGenerateSigner loads an Ed25519 signing key from config or generates one.
func loadOrGenerateSigner(ctx context.Context, hexKey string) (*business.ChainSigner, error) {
	if hexKey != "" {
		return business.LoadPrivateKey(hexKey)
	}

	util.Log(ctx).Warn("AUDIT_SIGNING_KEY not set — generating ephemeral key. Set AUDIT_SIGNING_KEY in production.")
	return business.GenerateChainSigner()
}

// setupConnectServer creates the Connect RPC handler with the full interceptor chain:
// Auth → TenancyAccess → FunctionAccess → TenancyTx.
func setupConnectServer(
	ctx context.Context,
	sm security.Manager,
	implementation *handlers.AuditServer,
) http.Handler {
	authenticator := sm.GetAuthenticator(ctx)
	auth := sm.GetAuthorizer(ctx)

	// Layer 1: TenancyAccess — verifies data access to partition
	tenancyAccessChecker := authorizer.NewTenancyAccessChecker(auth, namespaceTenancyAccess)
	tenancyAccessInterceptor := connectInterceptors.NewTenancyAccessInterceptor(tenancyAccessChecker)

	// Layer 2: FunctionAccess — enforces per-RPC permissions from proto annotations
	sd := auditv1.File_audit_v1_audit_proto.Services().ByName("AuditService")
	procMap := permissions.BuildProcedureMap(sd)
	svcPerms := permissions.ForService(sd)
	functionChecker := authorizer.NewFunctionChecker(auth, svcPerms.Namespace)
	functionAccessInterceptor := connectInterceptors.NewFunctionAccessInterceptor(functionChecker, procMap)

	defaultInterceptorList, err := connectInterceptors.DefaultList(ctx, authenticator,
		tenancyAccessInterceptor, functionAccessInterceptor)
	if err != nil {
		util.Log(ctx).WithError(err).Fatal("failed to create default interceptors")
	}

	_, serverHandler := auditv1connect.NewAuditServiceHandler(
		implementation, connect.WithInterceptors(defaultInterceptorList...))

	mux := http.NewServeMux()
	mux.Handle("/", serverHandler)

	return mux
}
