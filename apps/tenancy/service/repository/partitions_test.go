package repository_test

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/framedata"
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
		setupFunc   func(ctx context.Context, svc *frame.Service, t *testing.T) *models.Partition
	}{
		{
			name:        "Get existing partition by ID",
			shouldError: false,
			expectedErr: "",
			setupFunc: func(ctx context.Context, svc *frame.Service, t *testing.T) *models.Partition {
				tenantRepo := repository.NewTenantRepository(svc)
				partitionRepo := repository.NewPartitionRepository(svc)

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

				return &partition
			},
		},
		{
			name:        "Get non-existent partition",
			shouldError: true,
			expectedErr: "record not found",
			setupFunc: func(ctx context.Context, svc *frame.Service, t *testing.T) *models.Partition {
				return &models.Partition{BaseModel: frame.BaseModel{ID: "non-existent-id"}}
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				partition := tc.setupFunc(ctx, svc, t)

				// Execute
				savedPartition, err := repository.NewPartitionRepository(svc).GetByID(ctx, partition.GetID())

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
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Save(ctx, &tenant)
		require.NoError(t, err)

		partition1 := models.Partition{
			Name:        "Search Partition One",
			Description: "Some description here for search",
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &partition1)
		require.NoError(t, err)

		partition2 := models.Partition{
			Name:        "Search Partition Two",
			Description: "Another description for search",
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &partition2)
		require.NoError(t, err)

		testCases := []struct {
			name          string
			query         string
			properties    map[string]any
			expectedCount int
			shouldError   bool
		}{
			{
				name:          "Search by name",
				query:         "Search Partition One",
				properties:    nil,
				expectedCount: 1,
			},
			{
				name:          "Search by description",
				query:         "description for search",
				properties:    nil,
				expectedCount: 2,
			},
			{
				name:          "Search by partial name",
				query:         "Search",
				properties:    nil,
				expectedCount: 2,
			},
			{
				name:          "Search with no results",
				query:         "non-existent",
				properties:    nil,
				expectedCount: 0,
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
				searchQuery := framedata.NewSearchQuery(tc.query, tc.properties, 0, 10)

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
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Save(ctx, &tenant)
		require.NoError(t, err)

		partition := models.Partition{
			Name:        "To be deleted",
			Description: "This partition will be deleted",
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &partition)
		require.NoError(t, err)

		// Test deleting a partition with children (should fail)
		parentPartition := models.Partition{
			Name:        "Parent Partition",
			Description: "This partition has a child",
			BaseModel:   frame.BaseModel{TenantID: tenant.GetID()},
		}
		err = partitionRepo.Save(ctx, &parentPartition)
		require.NoError(t, err)

		childPartition := models.Partition{
			Name:     "Child Partition",
			ParentID: parentPartition.GetID(),
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &childPartition)
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
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

				// Child partition role
				childPartitionRole := models.PartitionRole{
					BaseModel: frame.BaseModel{
						PartitionID: childPartition.GetID(),
					},
					Name:       "Child Partition Role",
					Properties: frame.JSONMap{"description": "Child partition role description"},
				}

				err = partitionRepo.SaveRole(ctx, &childPartitionRole)
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
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Save(ctx, &tenant)
		require.NoError(t, err)

		// Create
		partition := models.Partition{
			Name:        "Save Test Partition",
			Description: "Save test description",
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &partition)
		require.NoError(t, err)
		assert.NotEmpty(t, partition.GetID())

		// Verify creation
		savedPartition, err := partitionRepo.GetByID(ctx, partition.GetID())
		require.NoError(t, err)
		assert.Equal(t, "Save Test Partition", savedPartition.Name)

		// Update
		savedPartition.Name = "Updated Partition Name"
		err = partitionRepo.Save(ctx, savedPartition)
		require.NoError(t, err)

		// Verify update
		updatedPartition, err := partitionRepo.GetByID(ctx, partition.GetID())
		require.NoError(t, err)
		assert.Equal(t, "Updated Partition Name", updatedPartition.Name)
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
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
					BaseModel: frame.BaseModel{
						PartitionID: partition.GetID(),
					},
					Name:       tc.roleName,
					Properties: frame.JSONMap{"description": "Test role description"},
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

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
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
					BaseModel: frame.BaseModel{
						PartitionID: partition.GetID(),
					},
					Name:       tc.roleName,
					Properties: frame.JSONMap{"description": "Test role description"},
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

func (suite *PartitionTestSuite) TestGetRoles() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Save(ctx, &tenant)
		require.NoError(t, err)

		partition := models.Partition{
			Name:        "Partition for roles",
			Description: "This partition has roles",
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &partition)
		require.NoError(t, err)

		role1 := models.PartitionRole{
			BaseModel: frame.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "Admin",
			Properties: frame.JSONMap{"description": "Administrator role"},
		}
		err = partitionRepo.SaveRole(ctx, &role1)
		require.NoError(t, err)

		role2 := models.PartitionRole{
			BaseModel: frame.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "User",
			Properties: frame.JSONMap{"description": "User role"},
		}
		err = partitionRepo.SaveRole(ctx, &role2)
		require.NoError(t, err)

		// Execute
		roles, err := partitionRepo.GetRoles(ctx, partition.GetID())
		require.NoError(t, err)

		// Verify
		assert.Len(t, roles, 2, "Should have two roles")
	})
}

func (suite *PartitionTestSuite) TestGetRolesByID() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		// Setup
		tenant := models.Tenant{
			Name:        "default",
			Description: "Test",
		}
		err := tenantRepo.Save(ctx, &tenant)
		require.NoError(t, err)

		partition := models.Partition{
			Name:        "Partition for roles",
			Description: "This partition has roles",
			BaseModel: frame.BaseModel{
				TenantID: tenant.GetID(),
			},
		}
		err = partitionRepo.Save(ctx, &partition)
		require.NoError(t, err)

		role1 := models.PartitionRole{
			BaseModel: frame.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "Admin",
			Properties: frame.JSONMap{"description": "Administrator role"},
		}
		err = partitionRepo.SaveRole(ctx, &role1)
		require.NoError(t, err)

		role2 := models.PartitionRole{
			BaseModel: frame.BaseModel{
				PartitionID: partition.GetID(),
			},
			Name:       "User",
			Properties: frame.JSONMap{"description": "User role"},
		}
		err = partitionRepo.SaveRole(ctx, &role2)
		require.NoError(t, err)

		// Execute
		roles, err := partitionRepo.GetRolesByID(ctx, role1.GetID(), role2.GetID())
		require.NoError(t, err)

		// Verify
		assert.Len(t, roles, 2, "Should have two roles")
	})
}

// TestPartitionRepository runs the partition repository test suite.
func TestPartitionRepository(t *testing.T) {
	suite.Run(t, new(PartitionTestSuite))
}
