package business_test

import (
	"context"
	"testing"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

type BusinessTestSuite struct {
	tests.BaseTestSuite
}

func TestBusinessTestSuite(t *testing.T) {
	suite.Run(t, new(BusinessTestSuite))
}

// createTestTenant creates a tenant via repo without claims (unscoped).
func (s *BusinessTestSuite) createTestTenant(ctx context.Context, deps *tests.DepsBuilder, name string) *models.Tenant {
	tenant := &models.Tenant{Name: name}
	err := deps.TenantRepo.Create(ctx, tenant)
	s.Require().NoError(err)
	return tenant
}

// createTestPartition creates a partition with PartitionID = its own ID (matching production pattern).
func (s *BusinessTestSuite) createTestPartition(
	ctx context.Context, deps *tests.DepsBuilder, tenantID string,
) *models.Partition {
	partitionID := util.IDString()
	partition := &models.Partition{
		Name: "P",
		BaseModel: data.BaseModel{
			ID:          partitionID,
			TenantID:    tenantID,
			PartitionID: partitionID, // self-referencing, matches production migration pattern
		},
	}
	err := deps.PartitionRepo.Create(ctx, partition)
	s.Require().NoError(err)
	return partition
}

// setupTenantAndPartition creates a tenant+partition and returns claims-scoped context.
func (s *BusinessTestSuite) setupTenantAndPartition(
	ctx context.Context, _ *frame.Service, deps *tests.DepsBuilder,
) (context.Context, *models.Partition) {
	tenant := s.createTestTenant(ctx, deps, "T")
	partition := s.createTestPartition(ctx, deps, tenant.GetID())
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())
	return ctx, partition
}

// ========================
// Tenant Business Tests
// ========================

func (s *BusinessTestSuite) TestCreateTenant() {
	s.T().Run("create_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			resp, err := deps.TenantBusiness.CreateTenant(ctx, &partitionv1.CreateTenantRequest{
				Name:        "Test Tenant",
				Description: "A test tenant",
			})

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Id)
			s.Require().Equal("Test Tenant", resp.Name)
			s.Require().Equal("A test tenant", resp.Description)
		})
	})
}

func (s *BusinessTestSuite) TestGetTenant() {
	s.T().Run("get_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "Get Me")
			tenant.Description = "Desc"

			// Match the scoping fields from the unscoped create
			ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

			fetched, err := deps.TenantBusiness.GetTenant(ctx, tenant.GetID())

			s.Require().NoError(err)
			s.Require().Equal(tenant.GetID(), fetched.Id)
			s.Require().Equal("Get Me", fetched.Name)
		})
	})
}

func (s *BusinessTestSuite) TestGetTenant_NotFound() {
	s.T().Run("get_tenant_not_found", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			resp, err := deps.TenantBusiness.GetTenant(ctx, "nonexistent")

			s.Require().Error(err)
			s.Require().Nil(resp)
		})
	})
}

func (s *BusinessTestSuite) TestUpdateTenant_Name() {
	s.T().Run("update_tenant_name", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "Original")
			ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

			updated, err := deps.TenantBusiness.UpdateTenant(ctx, &partitionv1.UpdateTenantRequest{
				Id:   tenant.GetID(),
				Name: "Updated",
			})

			s.Require().NoError(err)
			s.Require().Equal("Updated", updated.Name)
		})
	})
}

func (s *BusinessTestSuite) TestUpdateTenant_Properties() {
	s.T().Run("update_tenant_properties", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := &models.Tenant{
				Name:       "WithProps",
				Properties: data.JSONMap{"key1": "val1"},
			}
			err := deps.TenantRepo.Create(ctx, tenant)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

			props2, _ := structpb.NewStruct(map[string]any{"key2": "val2"})
			updated, err := deps.TenantBusiness.UpdateTenant(ctx, &partitionv1.UpdateTenantRequest{
				Id:         tenant.GetID(),
				Properties: props2,
			})

			s.Require().NoError(err)
			propsMap := updated.Properties.AsMap()
			s.Require().Equal("val1", propsMap["key1"])
			s.Require().Equal("val2", propsMap["key2"])
		})
	})
}

func (s *BusinessTestSuite) TestListTenant() {
	s.T().Run("list_tenants", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			for i := range 3 {
				_, err := deps.TenantBusiness.CreateTenant(ctx, &partitionv1.CreateTenantRequest{
					Name: util.IDString(),
				})
				s.Require().NoError(err, "failed creating tenant %d", i)
			}

			tenants, err := deps.TenantBusiness.ListTenant(ctx, &partitionv1.ListTenantRequest{Count: 50})

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(tenants), 3)
		})
	})
}

// ========================
// Partition Business Tests
// ========================

func (s *BusinessTestSuite) TestCreatePartition() {
	s.T().Run("create_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

			resp, err := deps.PartitionBusiness.CreatePartition(ctx, &partitionv1.CreatePartitionRequest{
				TenantId: tenant.GetID(),
				Name:     "New Partition",
			})

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Id)
			s.Require().Equal(tenant.GetID(), resp.TenantId)
			s.Require().Equal("New Partition", resp.Name)
		})
	})
}

func (s *BusinessTestSuite) TestCreatePartition_InvalidTenant() {
	s.T().Run("create_partition_invalid_tenant", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			resp, err := deps.PartitionBusiness.CreatePartition(ctx, &partitionv1.CreatePartitionRequest{
				TenantId: "nonexistent",
				Name:     "Fail",
			})

			s.Require().Error(err)
			s.Require().Nil(resp)
		})
	})
}

func (s *BusinessTestSuite) TestGetPartition() {
	s.T().Run("get_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)
			ctx, partition := s.setupTenantAndPartition(ctx, svc, deps)

			fetched, err := deps.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{
				Id: partition.GetID(),
			})

			s.Require().NoError(err)
			s.Require().Equal(partition.GetID(), fetched.Id)
			s.Require().Equal("P", fetched.Name)
		})
	})
}

func (s *BusinessTestSuite) TestGetPartition_ServiceMatrix() {
	s.T().Run("get_partition_service_matrix", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")

			partitionID := util.IDString()
			partition := &models.Partition{
				Name: "WithSecret",
				BaseModel: data.BaseModel{
					ID:          partitionID,
					TenantID:    tenant.GetID(),
					PartitionID: partitionID,
				},
				Properties: data.JSONMap{
					"client_secret": "s3cr3t",
				},
			}
			err := deps.PartitionRepo.Create(ctx, partition)
			s.Require().NoError(err)

			// service_matrix profile → client_secret in properties
			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), "service_matrix")

			fetched, err := deps.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{
				Id: partition.GetID(),
			})

			s.Require().NoError(err)
			props := fetched.Properties.AsMap()
			s.Require().Equal("s3cr3t", props["client_secret"])
		})
	})
}

func (s *BusinessTestSuite) TestGetPartition_NoClaims() {
	s.T().Run("get_partition_no_claims", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			resp, err := deps.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{
				Id: "anything",
			})

			s.Require().Error(err)
			s.Require().Nil(resp)
		})
	})
}

func (s *BusinessTestSuite) TestUpdatePartition() {
	s.T().Run("update_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)
			ctx, partition := s.setupTenantAndPartition(ctx, svc, deps)

			props, _ := structpb.NewStruct(map[string]any{"key": "val"})
			updated, err := deps.PartitionBusiness.UpdatePartition(ctx, &partitionv1.UpdatePartitionRequest{
				Id:          partition.GetID(),
				Name:        "Updated",
				Description: "New desc",
				Properties:  props,
			})

			s.Require().NoError(err)
			s.Require().Equal("Updated", updated.Name)
			s.Require().Equal("New desc", updated.Description)
			s.Require().Equal("val", updated.Properties.AsMap()["key"])
		})
	})
}

func (s *BusinessTestSuite) TestListPartition() {
	s.T().Run("list_partitions", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")

			sharedPartitionID := util.IDString()
			for i := range 3 {
				p := &models.Partition{
					Name: util.IDString(),
					BaseModel: data.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: sharedPartitionID,
					},
				}
				err := deps.PartitionRepo.Create(ctx, p)
				s.Require().NoError(err, "failed creating partition %d", i)
			}

			// Use empty subject to avoid profile_id filter in search query
			// (Partition table has no profile_id column)
			claims := &security.AuthenticationClaims{
				TenantID:    tenant.GetID(),
				PartitionID: sharedPartitionID,
			}
			ctx = claims.ClaimsToContext(ctx)

			partitions, err := deps.PartitionBusiness.ListPartition(ctx, &partitionv1.ListPartitionRequest{Count: 50})

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(partitions), 3)
		})
	})
}

func (s *BusinessTestSuite) TestGetPartitionParents() {
	s.T().Run("get_partition_parents", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")

			// Use shared partition_id so both parent and child can be found with same claims
			sharedPartitionID := util.IDString()

			parent := &models.Partition{
				Name: "Parent",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: sharedPartitionID,
				},
			}
			err := deps.PartitionRepo.Create(ctx, parent)
			s.Require().NoError(err)

			child := &models.Partition{
				Name:     "Child",
				ParentID: parent.GetID(),
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: sharedPartitionID,
				},
			}
			err = deps.PartitionRepo.Create(ctx, child)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), sharedPartitionID, util.IDString())

			parents, err := deps.PartitionBusiness.GetPartitionParents(ctx, &partitionv1.GetPartitionParentsRequest{
				Id: child.GetID(),
			})

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(parents), 1)
		})
	})
}

func (s *BusinessTestSuite) TestCreatePartitionRole() {
	s.T().Run("create_partition_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)
			ctx, partition := s.setupTenantAndPartition(ctx, svc, deps)

			resp, err := deps.PartitionBusiness.CreatePartitionRole(ctx, &partitionv1.CreatePartitionRoleRequest{
				PartitionId: partition.GetID(),
				Name:        "editor",
			})

			s.Require().NoError(err)
			s.Require().Equal("editor", resp.Name)
		})
	})
}

func (s *BusinessTestSuite) TestListPartitionRoles() {
	s.T().Run("list_partition_roles", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			for _, name := range []string{"admin", "member"} {
				role := &models.PartitionRole{
					Name: name,
					BaseModel: data.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}
				err := deps.PartitionRoleRepo.Create(ctx, role)
				s.Require().NoError(err)
			}

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			resp, err := deps.PartitionBusiness.ListPartitionRoles(ctx, &partitionv1.ListPartitionRoleRequest{
				PartitionId: partition.GetID(),
			})

			s.Require().NoError(err)
			s.Require().GreaterOrEqual(len(resp.GetRole()), 2)
		})
	})
}

func (s *BusinessTestSuite) TestRemovePartitionRole() {
	s.T().Run("remove_partition_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			role := &models.PartitionRole{
				Name: "temp",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PartitionRoleRepo.Create(ctx, role)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			err = deps.PartitionBusiness.RemovePartitionRole(ctx, &partitionv1.RemovePartitionRoleRequest{
				Id: role.GetID(),
			})
			s.Require().NoError(err)

			// Verify it's gone
			roles, err := deps.PartitionRoleRepo.GetRolesByID(ctx, role.GetID())
			s.Require().NoError(err)
			s.Require().Empty(roles)
		})
	})
}

// ========================
// Access Business Tests
// ========================

func (s *BusinessTestSuite) TestCreateAccess() {
	s.T().Run("create_access", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)
			ctx, partition := s.setupTenantAndPartition(ctx, svc, deps)

			newProfileID := util.IDString()
			createAccessReq := &partitionv1.CreateAccessRequest{
				ProfileId: newProfileID,
			}
			createAccessReq.SetPartitionId(partition.GetID())
			resp, err := deps.AccessBusiness.CreateAccess(ctx, createAccessReq)

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Id)
			s.Require().Equal(newProfileID, resp.ProfileId)
			s.Require().Equal(partition.GetID(), resp.Partition.Id)
		})
	})
}

func (s *BusinessTestSuite) TestCreateAccess_Idempotent() {
	s.T().Run("create_access_idempotent", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)
			ctx, partition := s.setupTenantAndPartition(ctx, svc, deps)

			newProfileID := util.IDString()
			createReq := &partitionv1.CreateAccessRequest{
				ProfileId: newProfileID,
			}
			createReq.SetPartitionId(partition.GetID())

			resp1, err := deps.AccessBusiness.CreateAccess(ctx, createReq)
			s.Require().NoError(err)

			resp2, err := deps.AccessBusiness.CreateAccess(ctx, createReq)
			s.Require().NoError(err)
			s.Require().Equal(resp1.Id, resp2.Id)
		})
	})
}

func (s *BusinessTestSuite) TestGetAccess_ByID() {
	s.T().Run("get_access_by_id", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			accessProfileID := util.IDString()
			access := &models.Access{
				ProfileID: accessProfileID,
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			fetched, err := deps.AccessBusiness.GetAccess(ctx, &partitionv1.GetAccessRequest{
				AccessId: access.GetID(),
			})

			s.Require().NoError(err)
			s.Require().Equal(access.GetID(), fetched.Id)
			s.Require().Equal(accessProfileID, fetched.ProfileId)
			s.Require().NotNil(fetched.Partition)
		})
	})
}

func (s *BusinessTestSuite) TestGetAccess_ByPartitionAndProfile() {
	s.T().Run("get_access_by_partition_profile", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			accessProfileID := util.IDString()
			access := &models.Access{
				ProfileID: accessProfileID,
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			getReq := &partitionv1.GetAccessRequest{
				ProfileId: accessProfileID,
			}
			getReq.SetPartitionId(partition.GetID())
			fetched, err := deps.AccessBusiness.GetAccess(ctx, getReq)

			s.Require().NoError(err)
			s.Require().Equal(access.GetID(), fetched.Id)
		})
	})
}

func (s *BusinessTestSuite) TestRemoveAccess() {
	s.T().Run("remove_access", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			access := &models.Access{
				ProfileID: util.IDString(),
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			err = deps.AccessBusiness.RemoveAccess(ctx, &partitionv1.RemoveAccessRequest{
				Id: access.GetID(),
			})
			s.Require().NoError(err)

			// Verify it's gone
			_, err = deps.AccessRepo.GetByID(ctx, access.GetID())
			s.Require().Error(err)
		})
	})
}

func (s *BusinessTestSuite) TestCreateAccessRole() {
	s.T().Run("create_access_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			role := &models.PartitionRole{
				Name: "editor",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PartitionRoleRepo.Create(ctx, role)
			s.Require().NoError(err)

			access := &models.Access{
				ProfileID: util.IDString(),
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err = deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			resp, err := deps.AccessBusiness.CreateAccessRole(ctx, &partitionv1.CreateAccessRoleRequest{
				AccessId:        access.GetID(),
				PartitionRoleId: role.GetID(),
			})

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.AccessRoleId)
			s.Require().Equal(access.GetID(), resp.AccessId)
		})
	})
}

func (s *BusinessTestSuite) TestListAccessRoles() {
	s.T().Run("list_access_roles", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			role1 := &models.PartitionRole{
				Name: "admin",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PartitionRoleRepo.Create(ctx, role1)
			s.Require().NoError(err)

			role2 := &models.PartitionRole{
				Name: "member",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err = deps.PartitionRoleRepo.Create(ctx, role2)
			s.Require().NoError(err)

			access := &models.Access{
				ProfileID: util.IDString(),
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err = deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			for _, role := range []*models.PartitionRole{role1, role2} {
				ar := &models.AccessRole{
					AccessID:        access.GetID(),
					PartitionRoleID: role.GetID(),
					BaseModel: data.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}
				err = deps.AccessRoleRepo.Create(ctx, ar)
				s.Require().NoError(err)
			}

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			resp, err := deps.AccessBusiness.ListAccessRoles(ctx, &partitionv1.ListAccessRoleRequest{
				AccessId: access.GetID(),
			})

			s.Require().NoError(err)
			s.Require().Len(resp.GetRole(), 2)
		})
	})
}

func (s *BusinessTestSuite) TestRemoveAccessRole() {
	s.T().Run("remove_access_role", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			role := &models.PartitionRole{
				Name: "editor",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PartitionRoleRepo.Create(ctx, role)
			s.Require().NoError(err)

			access := &models.Access{
				ProfileID: util.IDString(),
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err = deps.AccessRepo.Create(ctx, access)
			s.Require().NoError(err)

			accessRole := &models.AccessRole{
				AccessID:        access.GetID(),
				PartitionRoleID: role.GetID(),
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err = deps.AccessRoleRepo.Create(ctx, accessRole)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			err = deps.AccessBusiness.RemoveAccessRole(ctx, &partitionv1.RemoveAccessRoleRequest{
				Id: accessRole.GetID(),
			})
			s.Require().NoError(err)

			// Verify it's gone
			roles, listErr := deps.AccessRoleRepo.GetByAccessID(ctx, access.GetID())
			s.Require().NoError(listErr)
			s.Require().Empty(roles)
		})
	})
}

// ========================
// Page Business Tests
// ========================

func (s *BusinessTestSuite) TestCreatePage() {
	s.T().Run("create_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, svc, deps := s.CreateService(t, depOpts)
			ctx, partition := s.setupTenantAndPartition(ctx, svc, deps)

			resp, err := deps.PageBusiness.CreatePage(ctx, &partitionv1.CreatePageRequest{
				PartitionId: partition.GetID(),
				Name:        "login",
				Html:        "<h1>Login</h1>",
			})

			s.Require().NoError(err)
			s.Require().NotEmpty(resp.Id)
			s.Require().Equal("login", resp.Name)
			s.Require().Equal("<h1>Login</h1>", resp.Html)
		})
	})
}

func (s *BusinessTestSuite) TestCreatePage_InvalidPartition() {
	s.T().Run("create_page_invalid_partition", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			resp, err := deps.PageBusiness.CreatePage(ctx, &partitionv1.CreatePageRequest{
				PartitionId: "nonexistent",
				Name:        "fail",
			})

			s.Require().Error(err)
			s.Require().Nil(resp)
		})
	})
}

func (s *BusinessTestSuite) TestGetPage() {
	s.T().Run("get_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			page := &models.Page{
				Name: "login",
				HTML: "<h1>Login</h1>",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PageRepo.Create(ctx, page)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			fetched, err := deps.PageBusiness.GetPage(ctx, &partitionv1.GetPageRequest{
				PartitionId: partition.GetID(),
				Name:        "login",
			})

			s.Require().NoError(err)
			s.Require().Equal("login", fetched.Name)
			s.Require().Equal("<h1>Login</h1>", fetched.Html)
		})
	})
}

func (s *BusinessTestSuite) TestGetPage_NotFound() {
	s.T().Run("get_page_not_found", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			profileID := util.IDString()
			tenantID := util.IDString()
			ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

			resp, err := deps.PageBusiness.GetPage(ctx, &partitionv1.GetPageRequest{
				PartitionId: "nonexistent",
				Name:        "nope",
			})

			s.Require().Error(err)
			s.Require().Nil(resp)
		})
	})
}

func (s *BusinessTestSuite) TestRemovePage() {
	s.T().Run("remove_page", func(t *testing.T) {
		s.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, deps := s.CreateService(t, depOpts)

			tenant := s.createTestTenant(ctx, deps, "T")
			partition := s.createTestPartition(ctx, deps, tenant.GetID())

			page := &models.Page{
				Name: "temp",
				HTML: "<p>Temp</p>",
				BaseModel: data.BaseModel{
					TenantID:    tenant.GetID(),
					PartitionID: partition.GetID(),
				},
			}
			err := deps.PageRepo.Create(ctx, page)
			s.Require().NoError(err)

			ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

			err = deps.PageBusiness.RemovePage(ctx, &partitionv1.RemovePageRequest{
				Id: page.GetID(),
			})
			s.Require().NoError(err)

			// Verify it's gone
			_, fetchErr := deps.PageBusiness.GetPage(ctx, &partitionv1.GetPageRequest{
				PartitionId: partition.GetID(),
				Name:        "temp",
			})
			s.Require().Error(fetchErr)
		})
	})
}
