package repository_test

import (
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/pitabwire/frame/tests/testdef"
)

type TenantTestSuite struct {
	tests.BaseTestSuite
}

func (suite *TenantTestSuite) SetupTest() {
	// This will be called before each test
}

func (suite *TenantTestSuite) TestSave() {
	// Test cases
	testCases := []struct {
		name        string
		tenantName  string
		description string
		shouldError bool
	}{
		{
			name:        "Save valid tenant",
			tenantName:  "Test Tenant",
			description: "Test tenant description",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        tc.tenantName,
					Description: tc.description,
				}

				// Execute
				err := tenantRepo.Save(ctx, &tenant)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.NotEmpty(t, tenant.GetID(), "Tenant ID should be set after save")
				}
			})
		}
	})
}

func (suite *TenantTestSuite) TestGetByID() {
	// Test cases
	testCases := []struct {
		name        string
		tenantName  string
		description string
		shouldError bool
	}{
		{
			name:        "Get tenant by ID",
			tenantName:  "Test Tenant",
			description: "Test tenant description",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        tc.tenantName,
					Description: tc.description,
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				// Execute
				savedTenant, err := tenantRepo.GetByID(ctx, tenant.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.Equal(t, tenant.GetID(), savedTenant.GetID(), "Tenant ID should match")
					assert.Equal(t, tc.tenantName, savedTenant.Name, "Tenant name should match")
					assert.Equal(t, tc.description, savedTenant.Description, "Tenant description should match")
				}
			})
		}
	})
}

func (suite *TenantTestSuite) TestDelete() {
	// Test cases
	testCases := []struct {
		name        string
		tenantName  string
		description string
		shouldError bool
	}{
		{
			name:        "Delete tenant",
			tenantName:  "Test Tenant",
			description: "Test tenant description",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		tenantRepo := repository.NewTenantRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        tc.tenantName,
					Description: tc.description,
				}

				err := tenantRepo.Save(ctx, &tenant)
				require.NoError(t, err)

				// Execute
				err = tenantRepo.Delete(ctx, tenant.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					// After deletion, getting the tenant should return an error
					_, getErr := tenantRepo.GetByID(ctx, tenant.GetID())
					require.Error(t, getErr, "Should return an error when getting a deleted tenant")
				}
			})
		}
	})
}

// TestTenantRepository runs the tenant repository test suite.
func TestTenantRepository(t *testing.T) {
	suite.Run(t, new(TenantTestSuite))
}
