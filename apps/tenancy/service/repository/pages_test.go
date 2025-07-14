package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/tests/testdef"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PageTestSuite struct {
	tests.BaseTestSuite
}

func (suite *PageTestSuite) TestGetByPartitionAndName() {
	// Test cases
	testCases := []struct {
		name        string
		pageName    string
		shouldError bool
	}{
		{
			name:        "Get page by partition and name",
			pageName:    "test",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		pageRepo := repository.NewPageRepository(svc)
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

				page := models.Page{
					Name: tc.pageName,
					HTML: "<div></div>",
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = pageRepo.Save(ctx, &page)
				require.NoError(t, err)

				// Execute
				savedPage, err := pageRepo.GetByPartitionAndName(ctx, partition.GetID(), page.Name)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, partition.GetID(), savedPage.PartitionID, "Page partition id should match parent partition id")
					require.Equal(t, page.GetID(), savedPage.GetID(), "Page ID should match saved page ID")
				}
			})
		}
	})
}

func (suite *PageTestSuite) TestSave() {
	// Test cases
	testCases := []struct {
		name        string
		pageName    string
		html        string
		shouldError bool
	}{
		{
			name:        "Save page",
			pageName:    "test",
			html:        "<div></div>",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		pageRepo := repository.NewPageRepository(svc)
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

				page := models.Page{
					Name: tc.pageName,
					HTML: tc.html,
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				// Execute
				err = pageRepo.Save(ctx, &page)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					savedPage, fetchErr := pageRepo.GetByID(ctx, page.GetID())
					require.NoError(t, fetchErr)
					assert.Equal(t, partition.GetID(), savedPage.PartitionID, "Page partition id should match parent partition id")
					assert.Equal(t, tc.pageName, savedPage.Name, "Page name should match")
					assert.Equal(t, tc.html, savedPage.HTML, "Page HTML should match")
				}
			})
		}
	})
}

func (suite *PageTestSuite) TestDelete() {
	// Test cases
	testCases := []struct {
		name        string
		shouldError bool
	}{
		{
			name:        "Delete page",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *testdef.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		pageRepo := repository.NewPageRepository(svc)
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

				page := models.Page{
					Name: "test",
					HTML: "<div></div>",
					BaseModel: frame.BaseModel{
						TenantID:    tenant.GetID(),
						PartitionID: partition.GetID(),
					},
				}

				err = pageRepo.Save(ctx, &page)
				require.NoError(t, err)

				// Execute
				err = pageRepo.Delete(ctx, page.GetID())

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					deletedPage, fetchErr := pageRepo.GetByID(ctx, page.GetID())
					require.Error(t, fetchErr, "Should get an error when fetching deleted page")
					assert.Contains(t, fetchErr.Error(), "record not found", "Error should mention 'record not found'")
					assert.Empty(t, deletedPage.GetID(), "Deleted page ID should be empty")
				}
			})
		}
	})
}

// TestPageRepository runs the page repository test suite.
func TestPageRepository(t *testing.T) {
	suite.Run(t, new(PageTestSuite))
}
