package repository_test

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PartitionTestSuite struct {
	tests.BaseTestSuite
}

func (suite *PartitionTestSuite) TestGetByID() {
	// Test cases
	testCases := []struct {
		name        string
		shouldError bool
		expectedErr string
		setupFunc   func(ctx context.Context, svc *frame.Service, deps *tests.DepsBuilder, t *testing.T) *models.Partition
	}{
		{
			name:        "Get existing partition by ID",
			shouldError: false,
			expectedErr: "",
			setupFunc: func(ctx context.Context, svc *frame.Service, deps *tests.DepsBuilder, t *testing.T) *models.Partition {
				tenantRepo := deps.TenantRepo
				partitionRepo := deps.PartitionRepo

				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Create(ctx, &tenant)
				require.NoError(t, err)

				partition := models.Partition{
					Name:        "Test Partition",
					Description: "Test partition description",
					BaseModel: data.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Create(ctx, &partition)
				require.NoError(t, err)

				return &partition
			},
		},
		{
			name:        "Get non-existent partition",
			shouldError: true,
			expectedErr: "record not found",
			setupFunc: func(ctx context.Context, svc *frame.Service, deps *tests.DepsBuilder, t *testing.T) *models.Partition {
				return &models.Partition{BaseModel: data.BaseModel{ID: "non-existent-id"}}
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				partition := tc.setupFunc(ctx, svc, deps, t)

				// Execute
				partitionRepo := deps.PartitionRepo
				savedPartition, err := partitionRepo.GetByID(ctx, partition.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectedErr)
				} else {
					require.NoError(t, err)
					assert.Equal(t, partition.GetID(), savedPartition.GetID(), "Partition IDs should match")
					assert.Equal(t, partition.Name, savedPartition.Name, "Partition names should match")
					assert.Equal(t, partition.Description, savedPartition.Description, "Partition descriptions should match")
				}
			})
		}
	})
}

func (suite *PartitionTestSuite) TestSearch() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Create(ctx, &tenant)
		require.NoError(t, err)

		partition1 := models.Partition{
			Name:        "Search Partition One",
			Description: "Some description here for search",
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &partition1)
		require.NoError(t, err)

		partition2 := models.Partition{
			Name:        "Search Partition Two",
			Description: "Another description for search",
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &partition2)
		require.NoError(t, err)
		testCases := []struct {
			name          string
			query         string
			properties    map[string]any
			expectedCount int
			shouldError   bool
		}{
			{
				name:          "Search by exact name",
				query:         "",
				properties:    map[string]any{"name": "Search Partition One"},
				expectedCount: 1,
			},
			{
				name:          "Search by tenant ID",
				query:         "",
				properties:    map[string]any{"tenant_id": partition1.TenantID},
				expectedCount: 2,
			},
			{
				name:          "Search by ID",
				query:         "",
				properties:    map[string]any{"id": partition1.GetID()},
				expectedCount: 1,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {


				searchQuery := data.NewSearchQuery(
					
					data.WithSearchFiltersAndByValue(tc.properties),
					data.WithSearchOffset(0),
					data.WithSearchLimit(10),
				)

				resultPipe, resultErr := partitionRepo.Search(ctx, searchQuery)
				require.NoError(t, resultErr)

				result, ok := resultPipe.ReadResult(ctx)
				require.True(t, ok)

				require.NoError(t, result.Error())
				assert.Len(t, result.Item(), tc.expectedCount)
			})
		}
	})
}

func (suite *PartitionTestSuite) TestDelete() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Create(ctx, &tenant)
		require.NoError(t, err)

		partition := models.Partition{
			Name:        "To be deleted",
			Description: "This partition will be deleted",
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &partition)
		require.NoError(t, err)

		// Test deleting a partition with children (should fail)
		parentPartition := models.Partition{
			Name:        "Parent Partition",
			Description: "This partition has a child",
			BaseModel:   data.BaseModel{TenantID: tenant.GetID()},
		}
		err = partitionRepo.Create(ctx, &parentPartition)
		require.NoError(t, err)

		childPartition := models.Partition{
			Name:     "Child Partition",
			ParentID: parentPartition.GetID(),
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &childPartition)
		require.NoError(t, err)

		err = partitionRepo.Delete(ctx, parentPartition.GetID())
		require.Error(t, err)

		// Execute
		err = partitionRepo.Delete(ctx, partition.GetID())
		require.NoError(t, err)

		// Verify
		_, err = partitionRepo.GetByID(ctx, partition.GetID())
		assert.Error(t, err, "Expected an error when getting a deleted partition")
		assert.Contains(t, err.Error(), "record not found", "Error should indicate record not found")
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo
		partitionRoleRepo := deps.PartitionRoleRepo

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Create(ctx, &tenant)
				require.NoError(t, err)

				// Parent partition
				parentPartition := models.Partition{
					Name:        "Parent Partition",
					Description: "Parent partition description",
					BaseModel: data.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Create(ctx, &parentPartition)
				require.NoError(t, err)

				// Child partition
				childPartition := models.Partition{
					Name:        "Child Partition",
					Description: "Child partition description",
					ParentID:    parentPartition.GetID(),
					BaseModel: data.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Create(ctx, &childPartition)
				require.NoError(t, err)

				// Child partition role
				childPartitionRole := models.PartitionRole{
					BaseModel: data.BaseModel{
						PartitionID: childPartition.GetID(),
					},
					Name:       "Child Partition Role",
					Properties: data.JSONMap{"description": "Child partition role description"},
				}

				err = partitionRoleRepo.Create(ctx, &childPartitionRole)
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

func (suite *PartitionTestSuite) TestSave() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Create(ctx, &tenant)
		require.NoError(t, err)

		// Create
		partition := models.Partition{
			Name:        "Save Test Partition",
			Description: "Save test description",
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &partition)
		require.NoError(t, err)
		assert.NotEmpty(t, partition.GetID())

		// Verify creation
		savedPartition, err := partitionRepo.GetByID(ctx, partition.GetID())
		require.NoError(t, err)
		assert.Equal(t, "Save Test Partition", savedPartition.Name)


		// Test completed successfully
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo
		partitionRoleRepo := deps.PartitionRoleRepo

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Create(ctx, &tenant)
				require.NoError(t, err)

				partition := models.Partition{
					Name:        "Test Partition",
					Description: "Test partition description",
					BaseModel: data.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Create(ctx, &partition)
				require.NoError(t, err)

				partitionRole := models.PartitionRole{
					BaseModel: data.BaseModel{
						PartitionID: partition.GetID(),
					},
					Name:       tc.roleName,
					Properties: data.JSONMap{"description": "Test role description"},
				}

				// Execute
				err = partitionRoleRepo.Create(ctx, &partitionRole)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					// Get roles and find the one with matching name
					roles, rolesErr := partitionRoleRepo.GetByPartitionID(ctx, partition.GetID())
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo
		partitionRoleRepo := deps.PartitionRoleRepo

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "default",
					Description: "Test",
				}

				err := tenantRepo.Create(ctx, &tenant)
				require.NoError(t, err)

				partition := models.Partition{
					Name:        "Test Partition",
					Description: "Test partition description",
					BaseModel: data.BaseModel{
						TenantID: tenant.GetID(),
					},
				}

				err = partitionRepo.Create(ctx, &partition)
				require.NoError(t, err)

				partitionRole := models.PartitionRole{
					BaseModel: data.BaseModel{
						PartitionID: partition.GetID(),
					},
					Name:       tc.roleName,
					Properties: data.JSONMap{"description": "Test role description"},
				}

				err = partitionRoleRepo.Create(ctx, &partitionRole)
				require.NoError(t, err)

				// Execute
				err = partitionRoleRepo.Delete(ctx, partitionRole.GetID())

				// Verify
				if tc.shouldError {
					assert.Error(t, err)
				} else {
					require.NoError(t, err)

					roles, rolesErr := partitionRoleRepo.GetByPartitionID(ctx, partition.GetID())
					require.NoError(t, rolesErr)
					assert.Empty(t, roles, "Should have no roles after deletion")
				}
			})
		}
	})
}

func (suite *PartitionTestSuite) TestGetRoles() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo
		partitionRoleRepo := deps.PartitionRoleRepo
		partitionRepo := deps.PartitionRepo

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Create(ctx, &tenant)
		require.NoError(t, err)

		partition := models.Partition{
			Name:        "Partition for roles",
			Description: "This partition has roles",
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &partition)
		require.NoError(t, err)

		role1 := models.PartitionRole{
			BaseModel: data.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "Admin",
			Properties: data.JSONMap{"description": "Administrator role"},
		}
		err = partitionRoleRepo.Create(ctx, &role1)
		require.NoError(t, err)

		role2 := models.PartitionRole{
			BaseModel: data.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "User",
			Properties: data.JSONMap{"description": "User role"},
		}
		err = partitionRoleRepo.Create(ctx, &role2)
		require.NoError(t, err)

		// Execute
		roles, err := partitionRoleRepo.GetByPartitionID(ctx, partition.GetID())
		require.NoError(t, err)

		// Verify
		assert.Len(t, roles, 2, "Should have two roles")
	})
}

func (suite *PartitionTestSuite) TestGetRolesByID() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		partitionRoleRepo := deps.PartitionRoleRepo
		tenantRepo := deps.TenantRepo
		partitionRepo := deps.PartitionRepo

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Create(ctx, &tenant)
		require.NoError(t, err)

		partition := models.Partition{
			Name:        "Partition for roles",
			Description: "This partition has roles",
			BaseModel: data.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Create(ctx, &partition)
		require.NoError(t, err)

		role1 := models.PartitionRole{
			BaseModel: data.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "Admin",
			Properties: data.JSONMap{"description": "Administrator role"},
		}
		err = partitionRoleRepo.Create(ctx, &role1)
		require.NoError(t, err)

		role2 := models.PartitionRole{
			BaseModel: data.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "User",
			Properties: data.JSONMap{"description": "User role"},
		}
		err = partitionRoleRepo.Create(ctx, &role2)
		require.NoError(t, err)

		// Execute
		roles, err := partitionRoleRepo.GetRolesByID(ctx, role1.GetID(), role2.GetID())
		require.NoError(t, err)

		// Verify
		assert.Len(t, roles, 2, "Should have two roles")
	})
}

// TestPartitionRepository runs the partition repository test suite.
func TestPartitionRepository(t *testing.T) {
	suite.Run(t, new(PartitionTestSuite))
}
