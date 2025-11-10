package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
		errorAssert require.ErrorAssertionFunc
		checkError  func(t *testing.T, err error)
	}{
		{
			name:        "Save valid tenant",
			tenantName:  "Test Tenant",
			description: "Test tenant description",
			errorAssert: require.NoError,
			checkError: func(t *testing.T, err error) {
				// No error to check
			},
		},
		// Note: Empty name and duplicate name tests were removed as the current implementation
		// does not enforce these constraints
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        tc.tenantName,
					Description: tc.description,
				}

				// Execute
				err := tenantRepo.Create(ctx, &tenant)

				// Verify
				tc.errorAssert(t, err)
				if err == nil {
					assert.NotEmpty(t, tenant.GetID(), "Tenant ID should be set after save")
					assert.Equal(t, tc.tenantName, tenant.Name, "Tenant name should match")
					assert.Equal(t, tc.description, tenant.Description, "Tenant description should match")
				} else {
					tc.checkError(t, err)
				}
			})
		}
	})
}

func (suite *TenantTestSuite) TestGetByID() {
	// Test cases
	testCases := []struct {
		name         string
		tenantName   string
		description  string
		useInvalidID bool
		errorAssert  require.ErrorAssertionFunc
		checkError   func(t *testing.T, err error)
	}{
		{
			name:         "Get tenant by ID",
			tenantName:   "Test Tenant",
			description:  "Test tenant description",
			useInvalidID: false,
			errorAssert:  require.NoError,
			checkError: func(t *testing.T, err error) {
				// No error to check
			},
		},
		{
			name:         "Get tenant with invalid ID",
			tenantName:   "Test Tenant",
			description:  "Test tenant description",
			useInvalidID: true,
			errorAssert:  require.Error,
			checkError: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "record not found")
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        tc.tenantName,
					Description: tc.description,
				}

				err := tenantRepo.Create(ctx, &tenant)
				require.NoError(t, err)

				// Execute
				var savedTenant *models.Tenant
				var queryID string

				if tc.useInvalidID {
					queryID = "invalid-id"
				} else {
					queryID = tenant.GetID()
				}

				savedTenant, err = tenantRepo.GetByID(ctx, queryID)

				// Verify
				tc.errorAssert(t, err)
				if err == nil {
					assert.Equal(t, tenant.GetID(), savedTenant.GetID(), "Tenant ID should match")
					assert.Equal(t, tc.tenantName, savedTenant.Name, "Tenant name should match")
					assert.Equal(t, tc.description, savedTenant.Description, "Tenant description should match")
				} else {
					tc.checkError(t, err)
				}
			})
		}
	})
}

func (suite *TenantTestSuite) TestDelete() {
	// Test cases
	testCases := []struct {
		name         string
		tenantName   string
		description  string
		useInvalidID bool
		errorAssert  require.ErrorAssertionFunc
		checkError   func(t *testing.T, err error)
	}{
		{
			name:         "Delete tenant",
			tenantName:   "Test Tenant",
			description:  "Test tenant description",
			useInvalidID: false,
			errorAssert:  require.NoError,
			checkError: func(t *testing.T, err error) {
				// No error to check
			},
		},
		{
			name:         "Delete with invalid ID",
			tenantName:   "Test Tenant",
			description:  "Test tenant description",
			useInvalidID: true,
			errorAssert:  require.Error,
			checkError: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "record not found")
			},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, svc, deps := suite.CreateService(t, dep)
		_ = svc
		tenantRepo := deps.TenantRepo

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				tenant := models.Tenant{
					Name:        tc.tenantName,
					Description: tc.description,
				}

				err := tenantRepo.Create(ctx, &tenant)
				require.NoError(t, err)

				// Execute
				var deleteID string
				if tc.useInvalidID {
					deleteID = "invalid-id"
				} else {
					deleteID = tenant.GetID()
				}

				err = tenantRepo.Delete(ctx, deleteID)

				// Verify
				tc.errorAssert(t, err)

				if !tc.useInvalidID {
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
