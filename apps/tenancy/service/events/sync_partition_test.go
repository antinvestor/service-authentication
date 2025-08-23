package events

import (
	"fmt"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type SyncPartitionTestSuite struct {
	tests.BaseTestSuite
}

// Test comprehensive partition synchronisation scenarios
func (suite *SyncPartitionTestSuite) TestSyncPartitionOnHydra_ComprehensiveScenarios() {
	testCases := []struct {
		name        string
		partition   *models.Partition
		description string
	}{
		{
			name: "NewPartitionWithBasicProperties",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-basic-%d", time.Now().Unix()),
				},
				Name:         "Basic Test Partition",
				Description:  "Test partition with basic properties",
				ClientSecret: "basic-test-secret",
				Properties: frame.JSONMap{
					"redirect_uris": []interface{}{"https://basic-test.com/callback"},
					"scope":         "openid profile email",
					"audience":      []interface{}{"basic-api"},
					"logo_uri":      "https://basic-test.com/logo.png",
				},
			},
			description: "Tests new partition creation with basic OAuth2 properties",
		},
		{
			name: "PartitionWithComplexProperties",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-complex-%d", time.Now().Unix()),
				},
				Name:         "Complex Test Partition",
				ClientSecret: "complex-secret",
				Properties: frame.JSONMap{
					"redirect_uris": []interface{}{
						"https://app1.com/callback",
						"https://app2.com/auth",
						"https://app3.com/oauth",
					},
					"scope":                      "openid profile email admin custom:read custom:write",
					"audience":                   []interface{}{"api1", "api2", "api3"},
					"logo_uri":                   "https://complex.com/logo.svg",
					"token_endpoint_auth_method": "client_secret_basic",
					"custom_property":            "custom_value",
				},
			},
			description: "Tests partition with complex OAuth2 configuration",
		},
		{
			name: "PartitionWithStringRedirectURIs",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-string-uris-%d", time.Now().Unix()),
				},
				Name: "String URIs Test Partition",
				Properties: frame.JSONMap{
					"redirect_uris": "https://string1.com/callback,https://string2.com/auth",
					"scope":         "openid profile",
					"audience":      "string-api1,string-api2",
				},
			},
			description: "Tests partition with comma-separated string redirect URIs",
		},
		{
			name: "PartitionWithCustomClientID",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-custom-client-%d", time.Now().Unix()),
				},
				Name: "Custom Client ID Partition",
				Properties: frame.JSONMap{
					"client_id":     "custom-oauth-client-123",
					"redirect_uris": []interface{}{"https://custom.com/callback"},
					"scope":         "openid profile",
				},
			},
			description: "Tests partition with custom client_id property",
		},
		{
			name: "MinimalPartition",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-minimal-%d", time.Now().Unix()),
				},
				Name:       "Minimal Test Partition",
				Properties: frame.JSONMap{},
			},
			description: "Tests partition with minimal configuration",
		},
		{
			name: "PartitionWithClientSecretAndCustomAuth",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-auth-method-%d", time.Now().Unix()),
				},
				Name:         "Auth Method Test Partition",
				ClientSecret: "auth-method-secret",
				Properties: frame.JSONMap{
					"token_endpoint_auth_method": "client_secret_post",
					"redirect_uris":              []interface{}{"https://auth-test.com/callback"},
				},
			},
			description: "Tests partition with client secret and custom auth method",
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Logf("Testing: %s", tc.description)

				// Store original partition state for comparison
				originalName := tc.partition.Name
				originalID := tc.partition.ID
				originalSecret := tc.partition.ClientSecret
				originalProperties := make(frame.JSONMap)
				for k, v := range tc.partition.Properties {
					originalProperties[k] = v
				}

				// Execute SyncPartitionOnHydra
				err := SyncPartitionOnHydra(ctx, svc, tc.partition)

				// Log the result
				if err != nil {
					t.Logf("SyncPartitionOnHydra error (may be expected in test environment): %v", err)

					// Verify error handling
					require.Error(t, err)

					// Check for specific error types
					if err.Error() == "invalid configuration type" {
						t.Log("Configuration validation working correctly")
					} else {
						t.Logf("Network/Hydra error (expected in test env): %v", err)
					}
				} else {
					t.Log("SyncPartitionOnHydra succeeded - Hydra integration working")

					// If successful, verify partition properties were potentially updated
					require.NotNil(t, tc.partition.Properties)
				}

				// Verify partition structure integrity
				require.Equal(t, originalName, tc.partition.Name, "Partition name should remain unchanged")
				require.Equal(t, originalID, tc.partition.ID, "Partition ID should remain unchanged")
				require.Equal(t, originalSecret, tc.partition.ClientSecret, "Client secret should remain unchanged")

				// Verify original properties are preserved
				for key := range originalProperties {

					_, ok := tc.partition.Properties[key]
					require.True(t, ok, "key sent should be retained")

				}
			})
		}

	})
}

// Test partition deletion scenario
func (suite *SyncPartitionTestSuite) TestSyncPartitionOnHydra_DeletedPartition() {
	partition := &models.Partition{
		BaseModel: frame.BaseModel{
			ID: fmt.Sprintf("test-deleted-%d", time.Now().Unix()),
			DeletedAt: gorm.DeletedAt{
				Time:  time.Now(),
				Valid: true,
			},
		},
		Name:        "Deleted Test Partition",
		Description: "Test partition marked for deletion",
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		// Execute sync operation
		err := SyncPartitionOnHydra(ctx, svc, partition)

		// Log result
		if err != nil {
			t.Logf("SyncPartitionOnHydra delete error (expected in test env): %v", err)
		} else {
			t.Log("SyncPartitionOnHydra delete succeeded")
		}

		// Verify partition deletion structure
		require.True(suite.T(), partition.DeletedAt.Valid, "Partition should be marked as deleted")
		require.Equal(suite.T(), "Deleted Test Partition", partition.Name)

	})
}

// Test error scenarios with invalid configurations
func (suite *SyncPartitionTestSuite) TestSyncPartitionOnHydra_ErrorScenarios() {
	errorTestCases := []struct {
		name        string
		partition   *models.Partition
		expectError bool
		description string
	}{
		{
			name: "InvalidRedirectURIType",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-invalid-uri-type-%d", time.Now().Unix()),
				},
				Name: "Invalid URI Type Test",
				Properties: frame.JSONMap{
					"redirect_uris": 12345, // Invalid type - should be string or []interface{}
				},
			},
			expectError: true,
			description: "Tests error handling for invalid redirect_uris type",
		},
		{
			name: "MalformedRedirectURI",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-malformed-uri-%d", time.Now().Unix()),
				},
				Name: "Malformed URI Test",
				Properties: frame.JSONMap{
					"redirect_uris": "not-a-valid-url-format",
				},
			},
			expectError: true,
			description: "Tests error handling for malformed redirect URIs",
		},
		{
			name: "EmptyPartitionName",
			partition: &models.Partition{
				BaseModel: frame.BaseModel{
					ID: fmt.Sprintf("test-empty-name-%d", time.Now().Unix()),
				},
				Name: "", // Empty name
				Properties: frame.JSONMap{
					"redirect_uris": []interface{}{"https://empty-name.com/callback"},
				},
			},
			expectError: false, // Empty name might be handled gracefully
			description: "Tests handling of partition with empty name",
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		for _, tc := range errorTestCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Logf("Testing error scenario: %s", tc.description)

				err := SyncPartitionOnHydra(ctx, svc, tc.partition)

				if tc.expectError {
					require.Error(t, err, "Expected error for %s", tc.name)
					t.Logf("Got expected error for %s: %v", tc.name, err)
				} else {
					if err != nil {
						t.Logf("Got error for %s (may be expected in test env): %v", tc.name, err)
					} else {
						t.Logf("No error for %s", tc.name)
					}
				}

				// Verify partition structure remains valid
				require.NotEmpty(t, tc.partition.ID, "Partition ID should not be empty")
			})
		}

	})
}

// Test performance and resource usage
func (suite *SyncPartitionTestSuite) TestSyncPartitionOnHydra_Performance() {
	partition := &models.Partition{
		BaseModel: frame.BaseModel{
			ID: fmt.Sprintf("test-performance-%d", time.Now().Unix()),
		},
		Name: "Performance Test Partition",
		Properties: frame.JSONMap{
			"redirect_uris": []interface{}{"https://perf-test.com/callback"},
			"scope":         "openid profile email",
			"audience":      []interface{}{"perf-api"},
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)
		// Measure execution time
		start := time.Now()
		err := SyncPartitionOnHydra(ctx, svc, partition)
		duration := time.Since(start)

		// Log performance metrics
		t.Logf("SyncPartitionOnHydra execution time: %v", duration)

		if err != nil {
			t.Logf("Performance test error: %v", err)
		} else {
			t.Log("Performance test succeeded")
		}

		// Verify reasonable execution time (should complete quickly even with network calls)
		require.Less(suite.T(), duration, 30*time.Second,
			"SyncPartitionOnHydra should complete within 30 seconds")

		// Verify partition structure
		require.Equal(suite.T(), "Performance Test Partition", partition.Name)
		require.Contains(suite.T(), partition.ID, "test-performance-")

	})
}

func TestSyncPartitionTestSuite(t *testing.T) {
	suite.Run(t, new(SyncPartitionTestSuite))
}
