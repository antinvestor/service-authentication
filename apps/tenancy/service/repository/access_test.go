package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AccessTestSuite struct {
	tests.BaseTestSuite
}

func (suite *AccessTestSuite) TestSave() {
	// Test cases
	testCases := []struct {
		name        string
		profileID   string
		errorAssert require.ErrorAssertionFunc
		checkError  func(t *testing.T, err error)
	}{
		{
			name:        "Save access",
			profileID:   "test-profile-id",
			errorAssert: require.NoError,
			checkError: func(t *testing.T, err error) {
				// No error to check
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		accessRepo := repository.NewAccessRepository(svc)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "Access T",
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

				access := models.Access{
					ProfileID: tc.profileID,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				// Execute
				err = accessRepo.Save(ctx, &access)

				// Verify
				tc.errorAssert(t, err)
				if err == nil {
					savedAccess, fetchErr := accessRepo.GetByID(ctx, access.GetID())
					require.NoError(t, fetchErr)
					assert.Equal(t, partition.GetID(), savedAccess.PartitionID, "Access partition id should match parent partition id")
					assert.Equal(t, tc.profileID, savedAccess.ProfileID, "Access profile id should match provided profile id")
				} else {
					tc.checkError(t, err)
				}
			})
		}
	})
}

func (suite *AccessTestSuite) TestGetByPartitionAndProfile() {
	// Test cases
	testCases := []struct {
		name        string
		profileID   string
		errorAssert require.ErrorAssertionFunc
		checkError  func(t *testing.T, err error)
	}{
		{
			name:        "Get access by partition and profile",
			profileID:   "test-profile-id",
			errorAssert: require.NoError,
			checkError: func(t *testing.T, err error) {
				// No error to check
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		accessRepo := repository.NewAccessRepository(svc)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "Access T",
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

				access := models.Access{
					ProfileID: tc.profileID,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = accessRepo.Save(ctx, &access)
				require.NoError(t, err)

				// Execute
				savedAccess, err := accessRepo.GetByPartitionAndProfile(ctx, partition.GetID(), tc.profileID)

				// Verify
				tc.errorAssert(t, err)
				if err == nil {
					assert.Equal(t, partition.GetID(), savedAccess.PartitionID, "Access partition id should match parent partition id")
					assert.Equal(t, tc.profileID, savedAccess.ProfileID, "Access profile id should match profile id")
				} else {
					tc.checkError(t, err)
				}
			})
		}
	})
}

func (suite *AccessTestSuite) TestSaveRole() {
	// Test cases
	testCases := []struct {
		name        string
		profileID   string
		roleName    string
		shouldError bool
	}{
		{
			name:        "Save access role",
			profileID:   "test-profile-id",
			roleName:    "test-role",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		accessRepo := repository.NewAccessRepository(svc)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "Access T",
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

				access := models.Access{
					ProfileID: tc.profileID,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = accessRepo.Save(ctx, &access)
				require.NoError(t, err)

				// Execute
				err = accessRepo.SaveRole(ctx, &models.AccessRole{
					AccessID:        access.GetID(),
					PartitionRoleID: partitionRole.GetID(),
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				})

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					roles, rolesErr := accessRepo.GetRoles(ctx, access.GetID())
					require.NoError(t, rolesErr)
					assert.Len(t, roles, 1, "There should be one access role")
					assert.Equal(t, partitionRole.GetID(), roles[0].PartitionRoleID, "Access role should have correct partition role ID")
				}
			})
		}
	})
}

func (suite *AccessTestSuite) TestRemoveRole() {
	// Test cases
	testCases := []struct {
		name        string
		profileID   string
		roleName    string
		shouldError bool
	}{
		{
			name:        "Remove access role",
			profileID:   "test-profile-id",
			roleName:    "test-role",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		accessRepo := repository.NewAccessRepository(svc)
		tenantRepo := repository.NewTenantRepository(svc)
		partitionRepo := repository.NewPartitionRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        "Access T",
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

				access := models.Access{
					ProfileID: tc.profileID,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = accessRepo.Save(ctx, &access)
				require.NoError(t, err)

				accessRole := models.AccessRole{
					AccessID:        access.GetID(),
					PartitionRoleID: partitionRole.GetID(),
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = accessRepo.SaveRole(ctx, &accessRole)
				require.NoError(t, err)

				// Execute
				err = accessRepo.RemoveRole(ctx, accessRole.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					roles, rolesErr := accessRepo.GetRoles(ctx, access.GetID())
					require.NoError(t, rolesErr)
					assert.Empty(t, roles, "There should be no access roles after deletion")
				}
			})
		}
	})
}

// TestAccessRepository runs the access repository test suite.
func TestAccessRepository(t *testing.T) {
	suite.Run(t, new(AccessTestSuite))
}
