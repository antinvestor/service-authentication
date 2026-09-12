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

// Package tests provides the shared integration test suite for the audit
// service: one Postgres container per suite, one Frame service per test with
// row-level security enforced, migrations applied, and a signing key on disk.
package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	internaltests "github.com/antinvestor/service-authentication/pkg/tests"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/frametests"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/frametests/deps/testpostgres"
	"github.com/pitabwire/frame/v2/frametests/rlstest"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/tenancy"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

// NamespaceAudit is the service name used for tenancy elevation in tests.
const NamespaceAudit = "service_audit"

// MigrationPath is relative to any package under apps/audit/service/*.
const MigrationPath = "../../migrations/0001"

// Service bundles what a test needs from a started audit service.
type Service struct {
	Ctx    context.Context
	Svc    *frame.Service
	Cfg    *aconfig.AuditConfig
	Pool   pool.Pool
	KeyDir string
	// DSN is the superuser connection string, for tests that must bypass
	// row-level security or the immutability triggers (tamper simulation).
	DSN string
}

// BaseTestSuite starts one Postgres container for the suite.
type BaseTestSuite struct {
	internaltests.BaseTestSuite
}

func initResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_audit",
		definition.WithUserName("ant"), definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false))
	return []definition.TestResource{pg}
}

func (bs *BaseTestSuite) SetupSuite() {
	bs.InitResourceFunc = initResources
	bs.BaseTestSuite.SetupSuite()
}

// WriteKeyFile generates an Ed25519 key, writes the hex seed to dir/keyID
// and returns the private key.
func WriteKeyFile(t *testing.T, dir, keyID string) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyID), []byte(hex.EncodeToString(priv.Seed())), 0o600))
	return priv
}

// CreateService starts a migrated audit service with RLS enforced and a
// fresh signing key "k1" in a temp directory. Configuration overrides may be
// applied through mutate before the service is constructed.
func (bs *BaseTestSuite) CreateService(t *testing.T, mutate func(cfg *aconfig.AuditConfig)) *Service {
	t.Helper()
	ctx := t.Context()

	var databaseDR definition.DependancyConn
	for _, res := range bs.Resources() {
		if res.Name() == testpostgres.PostgresqlDBImage {
			databaseDR = res
		}
	}
	require.NotNil(t, databaseDR)

	prefix := util.RandomAlphaNumericString(internaltests.DefaultRandomStringLength)
	testDS, cleanup, err := databaseDR.GetRandomisedDS(ctx, prefix)
	require.NoError(t, err)
	t.Cleanup(func() { cleanup(context.Background()) })

	keyDir := t.TempDir()
	WriteKeyFile(t, keyDir, "k1")

	cfg, err := config.FromEnv[aconfig.AuditConfig]()
	require.NoError(t, err)
	cfg.ServiceName = NamespaceAudit
	cfg.LogLevel = "info"
	cfg.AuthorizationMode = "disabled"
	cfg.DatabaseMigrate = true
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}
	cfg.SigningKeyRef = "file://" + filepath.Join(keyDir, "k1")
	cfg.SigningKeyID = "k1"
	cfg.SigningKeyMountDir = keyDir
	cfg.WriterTick = 20 * time.Millisecond
	cfg.WriterIdleTick = 50 * time.Millisecond
	cfg.WriterBatch = 100
	cfg.CheckpointEveryN = 50
	cfg.CheckpointInterval = time.Hour
	cfg.KeyReloadInterval = time.Hour
	if mutate != nil {
		mutate(&cfg)
	}

	require.NoError(t, rlstest.CreateRole(ctx, testDS.String()))
	rlsProv := rlstest.New()

	ctx, svc := frame.NewServiceWithContext(ctx,
		frame.WithName("audit_tests"),
		frame.WithConfig(&cfg),
		frame.WithTenancyProvider(rlsProv),
		frame.WithSystemPrincipalAllowGlobal(NamespaceAudit),
		frame.WithDatastore(),
		frametests.WithNoopDriver(),
	)
	t.Cleanup(func() {
		svc.Stop(context.Background())
		if dbMan := svc.DatastoreManager(); dbMan != nil {
			dbMan.Close(context.Background())
		}
		time.Sleep(200 * time.Millisecond)
	})

	svc.Init(ctx)
	require.NoError(t, repository.Migrate(ctx, svc.DatastoreManager(), MigrationPath))
	require.NoError(t, rlstest.GrantAll(ctx, testDS.String()))
	rlsProv.Enable()
	require.NoError(t, svc.Run(ctx, ""))

	return &Service{
		Ctx:    ctx,
		Svc:    svc,
		Cfg:    &cfg,
		Pool:   svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName),
		KeyDir: keyDir,
		DSN:    testDS.String(),
	}
}

// UserContext returns a context carrying claims for a person in the tenant.
func UserContext(ctx context.Context, tenantID, partitionID, profileID string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID: tenantID, PartitionID: partitionID, ProfileID: profileID, Roles: []string{"user"},
	}
	claims.Subject = profileID
	return claims.ClaimsToContext(ctx)
}

// ServiceAccountContext returns a context carrying service-account claims.
func ServiceAccountContext(ctx context.Context, tenantID, partitionID, profileID, serviceAccountID, serviceName string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID: tenantID, PartitionID: partitionID, ProfileID: profileID, ServiceName: serviceName,
		Roles: []string{"system_internal"},
		Ext:   map[string]any{"service_account_id": serviceAccountID, "service_name": serviceName},
	}
	claims.Subject = profileID
	return claims.ClaimsToContext(ctx)
}

// GlobalContext returns a context elevated to see every tenant's rows.
func GlobalContext(ctx context.Context) context.Context {
	return tenancy.WithSystemPrincipal(ctx, tenancy.SystemPrincipal{
		ServiceName: NamespaceAudit, AllowGlobal: true, Reason: "test",
	})
}

// SuperuserPool opens a separate pool on the superuser DSN. Use it only to
// simulate tampering or to inspect rows across tenants.
func (s *Service) SuperuserPool(t *testing.T) pool.Pool {
	t.Helper()
	p := pool.NewPool(s.Ctx, pool.WithTenancyProvider(nil))
	require.NoError(t, p.AddConnection(s.Ctx, pool.WithConnection(s.DSN, false),
		pool.WithPreferSimpleProtocol(true), pool.WithPreparedStatements(false)))
	t.Cleanup(func() { p.Close(context.Background()) })
	return p
}

// TenantContext returns a context scoped to one tenant without user claims.
func TenantContext(ctx context.Context, tenantID string) context.Context {
	return tenancy.WithSystemPrincipal(ctx, tenancy.SystemPrincipal{
		ServiceName: NamespaceAudit, TenantID: tenantID, Reason: "test",
	})
}
