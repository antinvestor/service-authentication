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
	ctx := s.WithAuthClaims(s.SuiteCtx, seededOpportunitiesTenantID, seededOpportunitiesPartitionID, util.IDString())

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
