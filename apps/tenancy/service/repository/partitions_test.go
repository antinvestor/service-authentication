package repository_test

import (
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/tests/testdef"
)

type PartitionTestSuite struct {
	tests.BaseTestSuite
}

func (suite *PartitionTestSuite) TestGetByID() {
	// Test cases
	testCases := []struct {
		name        string
		shouldError bool
	}{
		{
			name:        "Get partition by ID",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				partition := models.Partition{
					Name:        "Test Partition",
					Description: "Test partition description",
					BaseModel: frame.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Save(ctx, &partition)
				require.NoError(t, err)

				// Execute
				savedPartition, err := partitionRepo.GetByID(ctx, partition.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.Equal(t, partition.GetID(), savedPartition.GetID(), "Partition IDs should match")
				}
			})
		}
	})
}

func (suite *PartitionTestSuite) TestGetChildren() {
	// Test cases
	testCases := []struct {
		name        string
		shouldError bool
	}{
		{
			name:        "Get children partitions",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				// Parent partition
				parentPartition := models.Partition{
					Name:        "Parent Partition",
					Description: "Parent partition description",
					BaseModel: frame.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Save(ctx, &parentPartition)
				require.NoError(t, err)

				// Child partition
				childPartition := models.Partition{
					Name:        "Child Partition",
					Description: "Child partition description",
					ParentID:    parentPartition.GetID(),
					BaseModel: frame.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Save(ctx, &childPartition)
				require.NoError(t, err)

				// Execute
				children, err := partitionRepo.GetChildren(ctx, parentPartition.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.Len(t, children, 1, "Should have one child partition")
					assert.Equal(t, childPartition.GetID(), children[0].GetID(), "Child partition ID should match")
				}
			})
		}
	})
}

func (suite *PartitionTestSuite) TestSaveRole() {
	// Test cases
	testCases := []struct {
		name        string
		roleName    string
		shouldError bool
	}{
		{
			name:        "Save partition role",
			roleName:    "test-role",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				partition := models.Partition{
					Name:        "Test Partition",
					Description: "Test partition description",
					BaseModel: frame.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Save(ctx, &partition)
				require.NoError(t, err)

				partitionRole := models.PartitionRole{
					Name: tc.roleName,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				// Execute
				err = partitionRepo.SaveRole(ctx, &partitionRole)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					// Get roles and find the one with matching name
					roles, rolesErr := partitionRepo.GetRoles(ctx, partition.GetID())
					require.NoError(t, rolesErr)

					var savedRole *models.PartitionRole
					for _, role := range roles {
						if role.Name == partitionRole.Name {
							savedRole = role
							break
						}
					}

					assert.NotNil(t, savedRole, "Should find the saved role")
					assert.Equal(t, partition.GetID(), savedRole.PartitionID, "Partition role partition id should match parent partition id")
					assert.Equal(t, partitionRole.GetID(), savedRole.GetID(), "Role ID should match saved role ID")
				}
			})
		}
	})
}

func (suite *PartitionTestSuite) TestRemoveRole() {
	// Test cases
	testCases := []struct {
		name        string
		roleName    string
		shouldError bool
	}{
		{
			name:        "Remove partition role",
			roleName:    "test-role",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				partition := models.Partition{
					Name:        "Test Partition",
					Description: "Test partition description",
					BaseModel: frame.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Save(ctx, &partition)
				require.NoError(t, err)

				partitionRole := models.PartitionRole{
					Name: tc.roleName,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = partitionRepo.SaveRole(ctx, &partitionRole)
				require.NoError(t, err)

				// Execute
				err = partitionRepo.RemoveRole(ctx, partitionRole.GetID())

				// Verify
				if tc.shouldError {
					assert.Error(t, err)
				} else {
					require.NoError(t, err)

					roles, rolesErr := partitionRepo.GetRoles(ctx, partition.GetID())
					require.NoError(t, rolesErr)
					assert.Empty(t, roles, "Should have no roles after deletion")
				}
			})
		}
	})
}

// TestPartitionRepository runs the partition repository test suite.
func TestPartitionRepository(t *testing.T) {
	suite.Run(t, new(PartitionTestSuite))
}
