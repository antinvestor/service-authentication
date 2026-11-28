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

package business_test

import (
	"context"
	"fmt"
	"os"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/jackc/pgx/v5"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// Seeded "Stawi Opportunities" tenant and partition
// (migrations/0001/20260704_01_greenfield_seed.sql).
const (
	seededOpportunitiesTenantID    = "d7gi6lkpf2t67dlsqre0"
	seededOpportunitiesPartitionID = "d7gi6lkpf2t67dlsqreg"
	// Tenant rows are scoped to the platform root that owns them.
	seededRootTenantID    = "c2f4j7au6s7f91uqnojg"
	seededRootPartitionID = "c2f4j7au6s7f91uqnokg"
)

// baseModelTables lists every BaseModel table tenancy migrates. Each must hold
// a non-NULL version: BaseRepository.Update filters "version = ?" and NULL
// never matches, so such a row can never be updated.
var baseModelTables = []string{
	"tenants", "partitions", "partition_roles", "accesses", "access_roles",
	"pages", "clients", "service_accounts", "service_namespaces",
	"oauth_client_recipients",
	"service_account_authorization_policies",
	"service_account_authorization_grants",
	"service_account_authorization_permissions",
	"service_account_applied_tuples",
}

func (s *BusinessTestSuite) adminConn() *pgx.Conn {
	conn, err := pgx.Connect(s.SuiteCtx, s.SuiteDeps.AdminDSN)
	s.Require().NoError(err)
	s.T().Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func (s *BusinessTestSuite) TestMigrations_LeaveNoBaseModelRowWithNullVersion() {
	conn := s.adminConn()

	for _, table := range baseModelTables {
		var nullRows int64
		err := conn.QueryRow(s.SuiteCtx,
			fmt.Sprintf("SELECT count(*) FROM public.%s WHERE version IS NULL", table),
		).Scan(&nullRows)
		s.Require().NoError(err, "table %s", table)
		s.Equal(int64(0), nullRows, "table %s has rows with NULL version; Frame updates can never match them", table)
	}
}

func (s *BusinessTestSuite) TestUpdatePartition_SeededPartitionPersistsSupportEmail() {
	deps := s.SuiteDeps
	actorID := util.IDString()
	ctx := s.WithAuthClaims(s.SuiteCtx, seededOpportunitiesTenantID, seededOpportunitiesPartitionID, actorID)

	before, err := deps.PartitionRepo.GetByID(ctx, seededOpportunitiesPartitionID)
	s.Require().NoError(err)
	originalContacts := before.Properties["support_contacts"]
	s.T().Cleanup(func() {
		restore, _ := structpb.NewStruct(map[string]any{"support_contacts": originalContacts})
		_, _ = deps.PartitionBusiness.UpdatePartition(ctx, &tenancyv1.UpdatePartitionRequest{
			Id: seededOpportunitiesPartitionID, Properties: restore,
		})
	})

	props, err := structpb.NewStruct(map[string]any{
		"support_contacts": map[string]any{"email": "hello@stawi.org"},
	})
	s.Require().NoError(err)

	updated, err := deps.PartitionBusiness.UpdatePartition(ctx, &tenancyv1.UpdatePartitionRequest{
		Id:         seededOpportunitiesPartitionID,
		Properties: props,
	})
	s.Require().NoError(err)
	s.Equal("hello@stawi.org", updated.GetProperties().AsMap()["support_contacts"].(map[string]any)["email"])

	stored, err := deps.PartitionRepo.GetByID(ctx, seededOpportunitiesPartitionID)
	s.Require().NoError(err)
	contacts, ok := stored.Properties["support_contacts"].(map[string]any)
	s.Require().True(ok, "support_contacts must be persisted as an object, got %T", stored.Properties["support_contacts"])
	s.Equal("hello@stawi.org", contacts["email"], "the update must be persisted, not only echoed back")
	s.Equal("Stawi Opportunities", stored.Name, "untouched columns keep their seeded value")
	s.Greater(stored.Version, before.Version, "a successful update advances the stored version")
	s.Equal(actorID, stored.ModifiedBy, "modified_by records the acting profile")
}

func (s *BusinessTestSuite) TestUpdateTenant_SeededTenantPersistsDescription() {
	deps := s.SuiteDeps
	ctx := s.WithAuthClaims(s.SuiteCtx, seededRootTenantID, seededRootPartitionID, util.IDString())

	before, err := deps.TenantRepo.GetByID(ctx, seededOpportunitiesTenantID)
	s.Require().NoError(err)
	s.T().Cleanup(func() {
		_, _ = deps.TenantBusiness.UpdateTenant(ctx, &tenancyv1.UpdateTenantRequest{
			Id: seededOpportunitiesTenantID, Description: before.Description,
		})
	})

	_, err = deps.TenantBusiness.UpdateTenant(ctx, &tenancyv1.UpdateTenantRequest{
		Id:          seededOpportunitiesTenantID,
		Description: "Updated seeded tenant",
	})
	s.Require().NoError(err)

	stored, err := deps.TenantRepo.GetByID(ctx, seededOpportunitiesTenantID)
	s.Require().NoError(err)
	s.Equal("Updated seeded tenant", stored.Description)
}

func (s *BusinessTestSuite) TestUpdateVersioned_StaleVersionReturnsConflict() {
	deps := s.SuiteDeps
	tenant := s.createTestTenant("Stale")
	partition := s.createTestPartition(tenant.GetID())
	ctx := s.WithAuthClaims(s.SuiteCtx, tenant.GetID(), partition.GetID(), util.IDString())

	first, err := deps.PartitionRepo.GetByID(ctx, partition.GetID())
	s.Require().NoError(err)
	stale, err := deps.PartitionRepo.GetByID(ctx, partition.GetID())
	s.Require().NoError(err)

	first.Name = "first writer"
	s.Require().NoError(repository.UpdateVersioned(ctx, deps.PartitionRepo, first, "name"))

	stale.Name = "stale writer"
	err = repository.UpdateVersioned(ctx, deps.PartitionRepo, stale, "name")
	s.Require().ErrorIs(err, repository.ErrUpdateConflict)

	stored, err := deps.PartitionRepo.GetByID(ctx, partition.GetID())
	s.Require().NoError(err)
	s.Equal("first writer", stored.Name, "the stale write must not overwrite the newer one")
	s.Equal(first.Version, stored.Version)
}

func (s *BusinessTestSuite) TestUpdateCallSites_ZeroRowsReturnConflict() {
	deps := s.SuiteDeps
	conn := s.adminConn()

	tenant := s.createTestTenant("ZeroRows")
	partition := s.createTestPartition(tenant.GetID())
	ctx := s.WithAuthClaims(s.SuiteCtx, tenant.GetID(), partition.GetID(), util.IDString())

	role, err := deps.PartitionBusiness.CreatePartitionRole(ctx, &tenancyv1.CreatePartitionRoleRequest{
		PartitionId: partition.GetID(),
		Name:        "zero-rows-role",
	})
	s.Require().NoError(err)

	// A NULL version is what seeds used to write; no update can match it.
	for _, stmt := range []struct{ table, id string }{
		{"tenants", tenant.GetID()},
		{"partitions", partition.GetID()},
		{"partition_roles", role.GetId()},
	} {
		_, err = conn.Exec(s.SuiteCtx,
			fmt.Sprintf("UPDATE public.%s SET version = NULL WHERE id = $1", stmt.table), stmt.id)
		s.Require().NoError(err)
	}

	cases := []struct {
		name string
		run  func() error
	}{
		{"UpdatePartition", func() error {
			_, e := deps.PartitionBusiness.UpdatePartition(ctx, &tenancyv1.UpdatePartitionRequest{
				Id: partition.GetID(), Name: "never persisted",
			})
			return e
		}},
		{"UpdateTenant", func() error {
			tenantCtx := s.WithAuthClaims(s.SuiteCtx, tenant.TenantID, tenant.PartitionID, util.IDString())
			_, e := deps.TenantBusiness.UpdateTenant(tenantCtx, &tenancyv1.UpdateTenantRequest{
				Id: tenant.GetID(), Name: "never persisted",
			})
			return e
		}},
		{"UpdatePartitionRole", func() error {
			_, e := deps.PartitionBusiness.UpdatePartitionRole(ctx, &tenancyv1.UpdatePartitionRoleRequest{
				Id: role.GetId(), Name: "never-persisted",
			})
			return e
		}},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.Require().ErrorIs(tc.run(), repository.ErrUpdateConflict,
				"an update that matched no row must not report success")
		})
	}
}

func (s *BusinessTestSuite) TestMigrations_FormstoreMayOnlyUploadToFiles() {
	conn := s.adminConn()

	var audiences int64
	err := conn.QueryRow(s.SuiteCtx, `
		SELECT count(*) FROM oauth_client_recipients r
		JOIN clients c ON c.id = r.client_ref
		WHERE c.client_id = 'operations-formstore' AND r.resource_audience = 'https://api.stawi.org/files'`,
	).Scan(&audiences)
	s.Require().NoError(err)
	s.Equal(int64(1), audiences, "formstore needs the files audience to call UploadContent")

	rows, err := conn.Query(s.SuiteCtx, `
		SELECT p.permission FROM service_account_authorization_permissions p
		JOIN service_account_authorization_grants g ON g.id = p.grant_id
		JOIN service_account_authorization_policies pol ON pol.id = g.policy_id
		JOIN service_accounts sa ON sa.id = pol.service_account_id
		WHERE sa.client_id = 'operations-formstore' AND g.namespace = 'service_file'`)
	s.Require().NoError(err)
	permissions, err := pgx.CollectRows(rows, pgx.RowTo[string])
	s.Require().NoError(err)
	s.Equal([]string{"content_upload"}, permissions, "formstore only uploads; it must not view, manage or delete files")
}

// TestFormstoreFilesMigration_ReusesExistingGrantAndRequeuesPolicy replays
// 20261128_02 against a state where the service_file grant already exists
// under another id: the replay must not abort on the (policy, namespace,
// scope) unique, must attach content_upload to the existing grant, and must
// requeue the policy and the Hydra client sync.
func (s *BusinessTestSuite) TestFormstoreFilesMigration_ReusesExistingGrantAndRequeuesPolicy() {
	ctx := s.SuiteCtx
	sqlFile, err := os.ReadFile("../../migrations/0001/20261128_02_formstore_files_upload.sql")
	s.Require().NoError(err)

	conn := s.adminConn()
	tx, err := conn.Begin(ctx)
	s.Require().NoError(err)
	// Rolled back: the replay is checked inside one transaction so the
	// reconciler cannot move the policy on before the assertions run.
	defer func() { _ = tx.Rollback(context.Background()) }()

	var policyID string
	var generation int64
	s.Require().NoError(tx.QueryRow(ctx, `
		SELECT pol.id, pol.generation FROM service_account_authorization_policies pol
		JOIN service_accounts sa ON sa.id = pol.service_account_id
		WHERE sa.client_id = 'operations-formstore'`).Scan(&policyID, &generation))

	existingGrantID := util.IDString()
	for _, stmt := range []string{
		`DELETE FROM service_account_authorization_permissions WHERE grant_id IN (
			SELECT id FROM service_account_authorization_grants WHERE policy_id = $1 AND namespace = 'service_file')`,
		`DELETE FROM service_account_authorization_grants WHERE policy_id = $1 AND namespace = 'service_file'`,
		`UPDATE service_account_authorization_policies
			SET status = 'failed', retry_count = 3, last_error_code = 'keto_unavailable', last_error = 'boom'
			WHERE id = $1`,
	} {
		_, err = tx.Exec(ctx, stmt, policyID)
		s.Require().NoError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_account_authorization_grants
		(id, created_at, modified_at, version, tenant_id, partition_id, policy_id, namespace, scope)
		SELECT $1, NOW(), NOW(), 1, tenant_id, partition_id, id, 'service_file', 'partition_tree'
		FROM service_account_authorization_policies WHERE id = $2`, existingGrantID, policyID)
	s.Require().NoError(err)
	_, err = tx.Exec(ctx, `UPDATE clients SET synced_at = NOW() WHERE client_id = 'operations-formstore'`)
	s.Require().NoError(err)

	_, err = tx.Exec(ctx, string(sqlFile))
	s.Require().NoError(err, "the migration must not abort when the grant already exists under another id")

	var status, lastErrorCode string
	var newGeneration, retryCount int64
	s.Require().NoError(tx.QueryRow(ctx, `SELECT generation, status, retry_count, COALESCE(last_error_code, '')
		FROM service_account_authorization_policies WHERE id = $1`, policyID).
		Scan(&newGeneration, &status, &retryCount, &lastErrorCode))
	s.Equal(generation+1, newGeneration, "the policy generation is bumped so the reconciler re-applies it")
	s.Equal("pending", status)
	s.Equal(int64(0), retryCount)
	s.Empty(lastErrorCode)

	var syncedAtCleared bool
	s.Require().NoError(tx.QueryRow(ctx,
		`SELECT synced_at IS NULL FROM clients WHERE client_id = 'operations-formstore'`).Scan(&syncedAtCleared))
	s.True(syncedAtCleared, "the Hydra client is re-synced to pick up the files audience")

	rows, err := tx.Query(ctx, `SELECT g.id, p.permission FROM service_account_authorization_grants g
		JOIN service_account_authorization_permissions p ON p.grant_id = g.id
		WHERE g.policy_id = $1 AND g.namespace = 'service_file'`, policyID)
	s.Require().NoError(err)
	type grantPermission struct {
		GrantID    string
		Permission string
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[grantPermission])
	s.Require().NoError(err)
	s.Equal([]grantPermission{{GrantID: existingGrantID, Permission: "content_upload"}}, got)
}
