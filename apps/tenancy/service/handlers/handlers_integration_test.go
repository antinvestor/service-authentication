package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type HandlerTestSuite struct {
	tests.BaseTestSuite
}

func TestHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
}

// seedOwner sets up Keto role + tenancy access + claims.
func (s *HandlerTestSuite) seedOwner(
	ctx context.Context, svc *frame.Service, tenantID, partitionID, profileID string,
) context.Context {
	s.SeedTenantRole(ctx, svc, tenantID, partitionID, profileID, authz.RoleOwner)
	s.SeedTenantAccess(ctx, svc, tenantID, partitionID, profileID)
	return s.WithAuthClaims(ctx, tenantID, partitionID, profileID)
}

// createTestPartition creates a partition with self-referencing PartitionID = ID,
// matching the production migration pattern. Must be called BEFORE seedOwner/claims
// so GenID does not override the explicit BaseModel fields.
func (s *HandlerTestSuite) createTestPartition(
	ctx context.Context, deps *tests.DepsBuilder, tenantID, name string,
) *models.Partition {
	partitionID := util.IDString()
	partition := &models.Partition{
		Name: name,
		BaseModel: data.BaseModel{
			ID:          partitionID,
			TenantID:    tenantID,
			PartitionID: partitionID,
		},
	}
	err := deps.PartitionRepo.Create(ctx, partition)
	s.Require().NoError(err)
	return partition
}

// ========================
// Tenant Handler Tests
// ========================

func (s *HandlerTestSuite) TestGetTenant_Success() {
	s.T().Run("get_existing_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			tenant := &models.Tenant{Name: "Test Tenant", Description: "A test tenant"}
			err := deps.TenantRepo.Create(ctx, tenant)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.GetTenantRequest{Id: tenant.GetID()})
			resp, err := deps.Server.GetTenant(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal(tenant.GetID(), resp.Msg.Data.Id)
			s.Require().Equal("Test Tenant", resp.Msg.Data.Name)
		})
	})
}

func (s *HandlerTestSuite) TestGetTenant_NotFound() {
	s.T().Run("get_nonexistent_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.GetTenantRequest{Id: "nonexistent"})
			resp, err := deps.Server.GetTenant(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
			st, ok := status.FromError(err)
			s.Require().True(ok)
			s.Require().Equal(codes.NotFound, st.Code())
		})
	})
}

func (s *HandlerTestSuite) TestGetTenant_NoAuthz() {
	s.T().Run("get_tenant_no_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.GetTenantRequest{Id: tenantID})
			resp, err := deps.Server.GetTenant(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestCreateTenant_Success() {
	s.T().Run("create_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.CreateTenantRequest{
				Name:        "New Tenant",
				Description: "Created via test",
			})
			resp, err := deps.Server.CreateTenant(ctx, req)

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Msg.Data.Id)
			s.Require().Equal("New Tenant", resp.Msg.Data.Name)
		})
	})
}

func (s *HandlerTestSuite) TestCreateTenant_NoAuthz() {
	s.T().Run("create_tenant_no_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

			req := connect.NewRequest(&partitionv1.CreateTenantRequest{Name: "Denied"})
			resp, err := deps.Server.CreateTenant(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestUpdateTenant_Success() {
	s.T().Run("update_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			tenant := &models.Tenant{Name: "Original", Description: "Desc"}
			err := deps.TenantRepo.Create(ctx, tenant)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.UpdateTenantRequest{
				Id:   tenant.GetID(),
				Name: "Updated",
			})
			resp, err := deps.Server.UpdateTenant(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal("Updated", resp.Msg.Data.Name)
		})
	})
}

func (s *HandlerTestSuite) TestUpdateTenant_NotFound() {
	s.T().Run("update_nonexistent_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.UpdateTenantRequest{Id: "nonexistent", Name: "Fail"})
			resp, err := deps.Server.UpdateTenant(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestListTenant_Success() {
	s.T().Run("list_tenants", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			for i := range 2 {
				tenant := &models.Tenant{Name: util.IDString(), Description: "tenant"}
				err := deps.TenantRepo.Create(ctx, tenant)
				s.Require().NoError(err, "failed creating tenant %d", i)
			}

			tenants, err := deps.TenantBusiness.ListTenant(ctx, &partitionv1.ListTenantRequest{Cursor: &commonv1.PageCursor{Limit: 50}})

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(tenants), 2)
		})
	})
}

// ========================
// Partition Handler Tests
// ========================

func (s *HandlerTestSuite) TestCreatePartition_Success() {
	s.T().Run("create_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			tenant := &models.Tenant{Name: "T", Description: "D"}
			err := deps.TenantRepo.Create(ctx, tenant)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.CreatePartitionRequest{
				TenantId: tenant.GetID(),
				Name:     "Test Partition",
			})
			resp, err := deps.Server.CreatePartition(ctx, req)

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Msg.Data.Id)
			s.Require().Equal("Test Partition", resp.Msg.Data.Name)
			s.Require().Equal(tenant.GetID(), resp.Msg.Data.TenantId)
		})
	})
}

func (s *HandlerTestSuite) TestCreatePartition_NoAuthz() {
	s.T().Run("create_partition_no_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

			req := connect.NewRequest(&partitionv1.CreatePartitionRequest{Name: "Denied"})
			resp, err := deps.Server.CreatePartition(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestGetPartition_Success() {
	s.T().Run("get_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "My Partition")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			req := connect.NewRequest(&partitionv1.GetPartitionRequest{Id: partition.GetID()})
			resp, err := deps.Server.GetPartition(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal(partition.GetID(), resp.Msg.Data.Id)
			s.Require().Equal("My Partition", resp.Msg.Data.Name)
		})
	})
}

func (s *HandlerTestSuite) TestGetPartition_NotFound() {
	s.T().Run("get_nonexistent_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.GetPartitionRequest{Id: "nonexistent"})
			resp, err := deps.Server.GetPartition(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
			st, ok := status.FromError(err)
			s.Require().True(ok)
			s.Require().Equal(codes.NotFound, st.Code())
		})
	})
}

func (s *HandlerTestSuite) TestListPartition_Success() {
	s.T().Run("list_partitions", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenantID := util.IDString()
			partitionID := util.IDString()

			// Use claims without Subject to avoid profile_id column filter
			// on the Partition table (buildSearchQuery adds profile_id when Subject is set).
			claims := &security.AuthenticationClaims{
				TenantID:    tenantID,
				PartitionID: partitionID,
			}
			ctx = claims.ClaimsToContext(ctx)

			for i := range 2 {
				p := &models.Partition{
					Name:      util.IDString(),
					BaseModel: data.BaseModel{TenantID: tenantID},
				}
				err := deps.PartitionRepo.Create(ctx, p)
				s.Require().NoError(err, "failed creating partition %d", i)
			}

			partitions, err := deps.PartitionBusiness.ListPartition(ctx, &partitionv1.ListPartitionRequest{Cursor: &commonv1.PageCursor{Limit: 50}})

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(partitions), 2)
		})
	})
}

func (s *HandlerTestSuite) TestUpdatePartition_Success() {
	s.T().Run("update_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "Original")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			req := connect.NewRequest(&partitionv1.UpdatePartitionRequest{
				Id:          partition.GetID(),
				Name:        "Updated",
				Description: "Updated desc",
			})
			resp, err := deps.Server.UpdatePartition(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal("Updated", resp.Msg.Data.Name)
			s.Require().Equal("Updated desc", resp.Msg.Data.Description)
		})
	})
}

func (s *HandlerTestSuite) TestGetPartitionParents_Success() {
	s.T().Run("get_partition_parents", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			parent := s.createTestPartition(ctx, deps, tenantID, "Parent")

			childID := util.IDString()
			child := &models.Partition{
				Name:     "Child",
				ParentID: parent.GetID(),
				BaseModel: data.BaseModel{
					ID:          childID,
					TenantID:    tenantID,
					PartitionID: parent.GetID(),
				},
			}
			err := deps.PartitionRepo.Create(ctx, child)
			s.Require().NoError(err)

			ctx = s.seedOwner(ctx, svc, tenantID, parent.GetID(), profileID)

			req := connect.NewRequest(&partitionv1.GetPartitionParentsRequest{Id: child.GetID()})
			resp, err := deps.Server.GetPartitionParents(ctx, req)

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(resp.Msg.Data), 1)
		})
	})
}

func (s *HandlerTestSuite) TestCreatePartitionRole_Success() {
	s.T().Run("create_partition_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			req := connect.NewRequest(&partitionv1.CreatePartitionRoleRequest{
				PartitionId: partition.GetID(),
				Name:        "editor",
			})
			resp, err := deps.Server.CreatePartitionRole(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal("editor", resp.Msg.Data.Name)
		})
	})
}

func (s *HandlerTestSuite) TestCreatePartitionRole_NoAuthz() {
	s.T().Run("create_partition_role_no_authz", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

			req := connect.NewRequest(&partitionv1.CreatePartitionRoleRequest{Name: "denied"})
			resp, err := deps.Server.CreatePartitionRole(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestListPartitionRoles_Success() {
	s.T().Run("list_partition_roles", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			for _, name := range []string{"admin", "member"} {
				role := &models.PartitionRole{
					Name: name,
				}
				err := deps.PartitionRoleRepo.Create(ctx, role)
				s.Require().NoError(err)
			}

			listReq := &partitionv1.ListPartitionRoleRequest{}
			listReq.SetPartitionId(partition.GetID())
			resp, err := deps.PartitionBusiness.ListPartitionRoles(ctx, listReq)

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(resp.GetData()), 2)
		})
	})
}

func (s *HandlerTestSuite) TestRemovePartitionRole_Success() {
	s.T().Run("remove_partition_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			role := &models.PartitionRole{Name: "temp"}
			err := deps.PartitionRoleRepo.Create(ctx, role)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.RemovePartitionRoleRequest{Id: role.GetID()})
			resp, err := deps.Server.RemovePartitionRole(ctx, req)

			s.Require().NoError(err)
			s.Require().True(resp.Msg.Succeeded)
		})
	})
}

func (s *HandlerTestSuite) TestRemovePartitionRole_NotFound() {
	s.T().Run("remove_nonexistent_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.RemovePartitionRoleRequest{Id: "nonexistent"})
			resp, err := deps.Server.RemovePartitionRole(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

// ========================
// Access Handler Tests
// ========================

func (s *HandlerTestSuite) TestCreateAccess_Success() {
	s.T().Run("create_access", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			newProfileID := util.IDString()
			createAccessReq := &partitionv1.CreateAccessRequest{
				ProfileId: newProfileID,
			}
			createAccessReq.SetPartitionId(partition.GetID())
			resp, err := deps.Server.CreateAccess(ctx, connect.NewRequest(createAccessReq))

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Msg.Data.Id)
			s.Require().Equal(newProfileID, resp.Msg.Data.ProfileId)
		})
	})
}

func (s *HandlerTestSuite) TestCreateAccess_Idempotent() {
	s.T().Run("create_access_idempotent", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			newProfileID := util.IDString()
			createReq := &partitionv1.CreateAccessRequest{
				ProfileId: newProfileID,
			}
			createReq.SetPartitionId(partition.GetID())
			resp1, err := deps.Server.CreateAccess(ctx, connect.NewRequest(createReq))
			s.Require().NoError(err)

			resp2, err := deps.Server.CreateAccess(ctx, connect.NewRequest(createReq))
			s.Require().NoError(err)
			s.Require().Equal(resp1.Msg.Data.Id, resp2.Msg.Data.Id)
		})
	})
}

func (s *HandlerTestSuite) TestCreateAccess_NoAuthz() {
	s.T().Run("create_access_no_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

			req := connect.NewRequest(&partitionv1.CreateAccessRequest{ProfileId: "p"})
			resp, err := deps.Server.CreateAccess(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestGetAccess_ByAccessId() {
	s.T().Run("get_access_by_id", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			accessProfileID := util.IDString()
			access := &models.Access{
				ProfileID: accessProfileID,
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.GetAccessRequest{AccessId: access.GetID()})
			resp, err := deps.Server.GetAccess(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal(access.GetID(), resp.Msg.Data.Id)
			s.Require().Equal(accessProfileID, resp.Msg.Data.ProfileId)
		})
	})
}

func (s *HandlerTestSuite) TestGetAccess_ByPartitionAndProfile() {
	s.T().Run("get_access_by_partition_profile", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			accessProfileID := util.IDString()
			access := &models.Access{
				ProfileID: accessProfileID,
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			getReq := &partitionv1.GetAccessRequest{
				ProfileId: accessProfileID,
			}
			getReq.SetPartitionId(partition.GetID())
			resp, err := deps.Server.GetAccess(ctx, connect.NewRequest(getReq))

			s.Require().NoError(err)
			s.Require().Equal(access.GetID(), resp.Msg.Data.Id)
		})
	})
}

func (s *HandlerTestSuite) TestGetAccess_NotFound() {
	s.T().Run("get_nonexistent_access", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.GetAccessRequest{AccessId: "nonexistent"})
			resp, err := deps.Server.GetAccess(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestRemoveAccess_Success() {
	s.T().Run("remove_access", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			access := &models.Access{ProfileID: util.IDString()}
			err := deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.RemoveAccessRequest{Id: access.GetID()})
			resp, err := deps.Server.RemoveAccess(ctx, req)

			s.Require().NoError(err)
			s.Require().True(resp.Msg.Succeeded)
		})
	})
}

func (s *HandlerTestSuite) TestCreateAccessRole_Success() {
	s.T().Run("create_access_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			role := &models.PartitionRole{Name: "editor"}
			err := deps.PartitionRoleRepo.Create(ctx, role)
			s.Require().NoError(err)

			access := &models.Access{ProfileID: util.IDString()}
			err = deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.CreateAccessRoleRequest{
				AccessId:        access.GetID(),
				PartitionRoleId: role.GetID(),
			})
			resp, err := deps.Server.CreateAccessRole(ctx, req)

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Msg.Data.Id)
		})
	})
}

func (s *HandlerTestSuite) TestListAccessRoles_Success() {
	s.T().Run("list_access_roles", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			role1 := &models.PartitionRole{Name: "admin"}
			err := deps.PartitionRoleRepo.Create(ctx, role1)
			s.Require().NoError(err)

			role2 := &models.PartitionRole{Name: "member"}
			err = deps.PartitionRoleRepo.Create(ctx, role2)
			s.Require().NoError(err)

			access := &models.Access{ProfileID: util.IDString()}
			err = deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			for _, role := range []*models.PartitionRole{role1, role2} {
				ar := &models.AccessRole{
					AccessID:        access.GetID(),
					PartitionRoleID: role.GetID(),
				}
				err = deps.AccessRoleRepo.Create(ctx, ar)
				s.Require().NoError(err)
			}

			listReq := &partitionv1.ListAccessRoleRequest{}
			listReq.SetAccessId(access.GetID())
			resp, err := deps.AccessBusiness.ListAccessRoles(ctx, listReq)

			s.Require().NoError(err)
			s.Require().Len(resp.GetData(), 2)
		})
	})
}

func (s *HandlerTestSuite) TestRemoveAccessRole_Success() {
	s.T().Run("remove_access_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			role := &models.PartitionRole{Name: "editor"}
			err := deps.PartitionRoleRepo.Create(ctx, role)
			s.Require().NoError(err)

			access := &models.Access{ProfileID: util.IDString()}
			err = deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			accessRole := &models.AccessRole{
				AccessID:        access.GetID(),
				PartitionRoleID: role.GetID(),
			}
			err = deps.AccessRoleRepo.Create(ctx, accessRole)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.RemoveAccessRoleRequest{Id: accessRole.GetID()})
			resp, err := deps.Server.RemoveAccessRole(ctx, req)

			s.Require().NoError(err)
			s.Require().True(resp.Msg.Succeeded)
		})
	})
}

func (s *HandlerTestSuite) TestRemoveAccessRole_NotFound() {
	s.T().Run("remove_nonexistent_access_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.RemoveAccessRoleRequest{Id: "nonexistent"})
			resp, err := deps.Server.RemoveAccessRole(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

// ========================
// Page Handler Tests
// ========================

func (s *HandlerTestSuite) TestCreatePage_Success() {
	s.T().Run("create_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			req := connect.NewRequest(&partitionv1.CreatePageRequest{
				PartitionId: partition.GetID(),
				Name:        "login",
				Html:        "<h1>Login</h1>",
			})
			resp, err := deps.Server.CreatePage(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal("login", resp.Msg.Data.Name)
			s.Require().Equal("<h1>Login</h1>", resp.Msg.Data.Html)
		})
	})
}

func (s *HandlerTestSuite) TestCreatePage_NoAuthz() {
	s.T().Run("create_page_no_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

			req := connect.NewRequest(&partitionv1.CreatePageRequest{Name: "denied"})
			resp, err := deps.Server.CreatePage(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestGetPage_Success() {
	s.T().Run("get_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			page := &models.Page{
				Name: "login",
				HTML: "<h1>Login</h1>",
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PageRepo.Create(ctx, page)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.GetPageRequest{
				PartitionId: partition.GetID(),
				Name:        "login",
			})
			resp, err := deps.Server.GetPage(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal("login", resp.Msg.Data.Name)
			s.Require().Equal("<h1>Login</h1>", resp.Msg.Data.Html)
		})
	})
}

func (s *HandlerTestSuite) TestGetPage_NotFound() {
	s.T().Run("get_nonexistent_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.GetPageRequest{
				PartitionId: "nonexistent",
				Name:        "nope",
			})
			resp, err := deps.Server.GetPage(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestRemovePage_Success() {
	s.T().Run("remove_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			page := &models.Page{
				Name: "temp",
				HTML: "<p>Temp</p>",
			}
			err := deps.PageRepo.Create(ctx, page)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.RemovePageRequest{Id: page.GetID()})
			resp, err := deps.Server.RemovePage(ctx, req)

			s.Require().NoError(err)
			s.Require().True(resp.Msg.Succeeded)
		})
	})
}

func (s *HandlerTestSuite) TestRemovePage_NotFound() {
	s.T().Run("remove_nonexistent_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.RemovePageRequest{Id: "nonexistent"})
			resp, err := deps.Server.RemovePage(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

// ========================
// Service Account Handler Tests
// ========================

func (s *HandlerTestSuite) TestCreateServiceAccount_Success() {
	s.T().Run("create_service_account", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "SA Test Partition")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			req := connect.NewRequest(&partitionv1.CreateServiceAccountRequest{
				PartitionId: partition.GetID(),
				ProfileId:   util.IDString(),
				Name:        "test-bot",
				Audiences:   []string{"service_profile", "service_tenancy"},
			})
			resp, err := deps.Server.CreateServiceAccount(ctx, req)

			s.Require().NoError(err)
			s.Require().NotNil(resp.Msg.Data)
			s.Require().NotEmpty(resp.Msg.Data.Id)
			s.Require().NotEmpty(resp.Msg.Data.ClientId)
			s.Require().NotEmpty(resp.Msg.ClientSecret, "ClientSecret should be returned on creation")
			s.Require().Equal(partition.GetID(), resp.Msg.Data.PartitionId)
			s.Require().Equal(tenantID, resp.Msg.Data.TenantId)
		})
	})
}

func (s *HandlerTestSuite) TestCreateServiceAccount_InvalidPartition() {
	s.T().Run("create_sa_invalid_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.CreateServiceAccountRequest{
				PartitionId: "nonexistent-partition",
				ProfileId:   util.IDString(),
				Name:        "should-fail",
			})
			resp, err := deps.Server.CreateServiceAccount(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestGetServiceAccount_ByID() {
	s.T().Run("get_sa_by_id", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			saProfileID := util.IDString()
			sa := &models.ServiceAccount{
				ProfileID:    saProfileID,
				ClientID:     util.IDString(),
				ClientSecret: "test-secret",
				Type:         "internal",
				Audiences:    data.JSONMap{"namespaces": []any{"svc1"}},
				Properties:   data.JSONMap{},
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.Server.ServiceAccountRepo.Create(ctx, sa)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.GetServiceAccountRequest{Id: sa.GetID()})
			resp, err := deps.Server.GetServiceAccount(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal(sa.GetID(), resp.Msg.Data.Id)
			s.Require().Equal(sa.ClientID, resp.Msg.Data.ClientId)
			s.Require().Equal(saProfileID, resp.Msg.Data.ProfileId)
		})
	})
}

func (s *HandlerTestSuite) TestGetServiceAccount_ByClientAndProfile() {
	s.T().Run("get_sa_by_client_and_profile", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			saProfileID := util.IDString()
			saClientID := util.IDString()
			sa := &models.ServiceAccount{
				ProfileID:    saProfileID,
				ClientID:     saClientID,
				ClientSecret: "test-secret",
				Type:         "external",
				Properties:   data.JSONMap{},
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.Server.ServiceAccountRepo.Create(ctx, sa)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.GetServiceAccountRequest{
				ClientId:  saClientID,
				ProfileId: saProfileID,
			})
			resp, err := deps.Server.GetServiceAccount(ctx, req)

			s.Require().NoError(err)
			s.Require().Equal(sa.GetID(), resp.Msg.Data.Id)
		})
	})
}

func (s *HandlerTestSuite) TestGetServiceAccount_NotFound() {
	s.T().Run("get_sa_not_found", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.GetServiceAccountRequest{Id: "nonexistent"})
			resp, err := deps.Server.GetServiceAccount(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
			st, ok := status.FromError(err)
			s.Require().True(ok)
			s.Require().Equal(codes.NotFound, st.Code())
		})
	})
}

func (s *HandlerTestSuite) TestRemoveServiceAccount_Success() {
	s.T().Run("remove_service_account", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			ctx = s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			sa := &models.ServiceAccount{
				ProfileID:    util.IDString(),
				ClientID:     util.IDString(),
				ClientSecret: "test-secret",
				Type:         "internal",
				Properties:   data.JSONMap{},
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.Server.ServiceAccountRepo.Create(ctx, sa)
			s.Require().NoError(err)

			req := connect.NewRequest(&partitionv1.RemoveServiceAccountRequest{Id: sa.GetID()})
			resp, err := deps.Server.RemoveServiceAccount(ctx, req)

			s.Require().NoError(err)
			s.Require().True(resp.Msg.Succeeded)

			// Verify SA is no longer retrievable
			getReq := connect.NewRequest(&partitionv1.GetServiceAccountRequest{Id: sa.GetID()})
			getResp, getErr := deps.Server.GetServiceAccount(ctx, getReq)
			s.Require().Nil(getResp)
			s.Require().Error(getErr)
		})
	})
}

func (s *HandlerTestSuite) TestRemoveServiceAccount_NotFound() {
	s.T().Run("remove_sa_not_found", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			req := connect.NewRequest(&partitionv1.RemoveServiceAccountRequest{Id: "nonexistent"})
			resp, err := deps.Server.RemoveServiceAccount(ctx, req)

			s.Require().Nil(resp)
			s.Require().Error(err)
		})
	})
}

func (s *HandlerTestSuite) TestGetServiceAccountByClientID_HTTP_Success() {
	s.T().Run("get_sa_by_client_id_http", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()

			partition := s.createTestPartition(ctx, deps, tenantID, "P")
			s.seedOwner(ctx, svc, tenantID, partition.GetID(), profileID)

			// Use system_internal role — this is an internal service endpoint
			ctx = s.WithAuthClaimsAndRoles(ctx, tenantID, partition.GetID(), profileID, []string{"system_internal"})

			clientID := util.IDString()
			sa := &models.ServiceAccount{
				ProfileID:    util.IDString(),
				ClientID:     clientID,
				ClientSecret: "test-secret",
				Type:         "internal",
				Properties:   data.JSONMap{},
				BaseModel: data.BaseModel{
					TenantID:    tenantID,
					PartitionID: partition.GetID(),
				},
			}
			err := deps.Server.ServiceAccountRepo.Create(ctx, sa)
			s.Require().NoError(err)

			// Build HTTP request using the mux pattern
			mux := http.NewServeMux()
			mux.HandleFunc(handlers.ServiceAccountByClientIDPath, deps.Server.GetServiceAccountByClientID)

			req := httptest.NewRequest(http.MethodGet, "/_system/service-account/by-client-id/"+clientID, nil)
			req = req.WithContext(ctx)
			rw := httptest.NewRecorder()

			mux.ServeHTTP(rw, req)

			s.Require().Equal(http.StatusOK, rw.Code)

			var body map[string]any
			err = json.Unmarshal(rw.Body.Bytes(), &body)
			s.Require().NoError(err)
			s.Require().Equal(clientID, body["clientId"])
		})
	})
}

func (s *HandlerTestSuite) TestGetServiceAccountByClientID_HTTP_NotFound() {
	s.T().Run("get_sa_by_client_id_http_not_found", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			// Use system_internal role — this is an internal service endpoint
			ctx = s.WithAuthClaimsAndRoles(ctx, tenantID, tenantID, profileID, []string{"system_internal"})

			mux := http.NewServeMux()
			mux.HandleFunc(handlers.ServiceAccountByClientIDPath, deps.Server.GetServiceAccountByClientID)

			req := httptest.NewRequest(http.MethodGet, "/_system/service-account/by-client-id/nonexistent", nil)
			req = req.WithContext(ctx)
			rw := httptest.NewRecorder()

			mux.ServeHTTP(rw, req)

			s.Require().Equal(http.StatusNotFound, rw.Code)
		})
	})
}

func (s *HandlerTestSuite) TestGetServiceAccountByClientID_HTTP_Forbidden() {
	s.T().Run("get_sa_by_client_id_http_forbidden", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			s.seedOwner(ctx, svc, tenantID, tenantID, profileID)

			// Regular user role — should be forbidden
			ctx = s.WithAuthClaimsAndRoles(ctx, tenantID, tenantID, profileID, []string{"user"})

			mux := http.NewServeMux()
			mux.HandleFunc(handlers.ServiceAccountByClientIDPath, deps.Server.GetServiceAccountByClientID)

			req := httptest.NewRequest(http.MethodGet, "/_system/service-account/by-client-id/some-id", nil)
			req = req.WithContext(ctx)
			rw := httptest.NewRecorder()

			mux.ServeHTTP(rw, req)

			s.Require().Equal(http.StatusForbidden, rw.Code)
		})
	})
}
