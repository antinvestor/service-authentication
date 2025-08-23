package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type APIKeyRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (suite *APIKeyRepositoryTestSuite) TestSave() {
	testCases := []struct {
		name        string
		profileID   string
		keyName     string
		key         string
		scope       string
		shouldError bool
	}{
		{
			name:        "Save new API key",
			profileID:   "test-profile-123",
			keyName:     "Test API Key",
			key:         "test-key-123",
			scope:       "[\"read\", \"write\"]",
			shouldError: false,
		},
		{
			name:        "Save API key with minimal data",
			profileID:   "test-profile-456",
			keyName:     "Minimal Key",
			key:         "minimal-key-456",
			scope:       "",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		apiKeyRepo := repository.NewAPIKeyRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				apiKey := &models.APIKey{
					BaseModel: frame.BaseModel{
						ID:          util.IDString(),
						TenantID:    "test-tenant",
						PartitionID: "test-partition",
					},
					ProfileID: tc.profileID,
					Name:      tc.keyName,
					Key:       tc.key,
					Scope:     tc.scope,
				}

				// Execute
				err := apiKeyRepo.Save(ctx, apiKey)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.NotEmpty(t, apiKey.ID, "API key ID should be set")
					assert.Equal(t, tc.profileID, apiKey.ProfileID, "Profile ID should match")
					assert.Equal(t, tc.keyName, apiKey.Name, "Key name should match")
					assert.Equal(t, tc.key, apiKey.Key, "Key should match")
				}
			})
		}
	})
}

func (suite *APIKeyRepositoryTestSuite) TestGetByID() {
	testCases := []struct {
		name       string
		profileID  string
		keyName    string
		key        string
		queryID    string
		shouldFind bool
	}{
		{
			name:       "Get existing API key by ID",
			profileID:  "test-profile-get-123",
			keyName:    "Get Test Key",
			key:        "get-test-key-123",
			queryID:    "", // Will be set to actual ID
			shouldFind: true,
		},
		{
			name:       "Get non-existing API key by ID",
			profileID:  "test-profile-get-456",
			keyName:    "Another Test Key",
			key:        "another-test-key-456",
			queryID:    "non-existing-id",
			shouldFind: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		apiKeyRepo := repository.NewAPIKeyRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup - create API key first
				apiKey := &models.APIKey{
					BaseModel: frame.BaseModel{
						ID:          util.IDString(),
						TenantID:    "test-tenant",
						PartitionID: "test-partition",
					},
					ProfileID: tc.profileID,
					Name:      tc.keyName,
					Key:       tc.key,
					Scope:     "",
				}

				err := apiKeyRepo.Save(ctx, apiKey)
				require.NoError(t, err)

				// Set query ID for valid test case
				queryID := tc.queryID
				if tc.shouldFind {
					queryID = apiKey.ID
				}

				// Execute
				foundAPIKey, err := apiKeyRepo.GetByID(ctx, queryID)

				// Verify
				if tc.shouldFind {
					require.NoError(t, err)
					require.NotNil(t, foundAPIKey, "Should find API key")
					assert.Equal(t, apiKey.ID, foundAPIKey.ID, "API key ID should match")
					assert.Equal(t, tc.profileID, foundAPIKey.ProfileID, "Profile ID should match")
					assert.Equal(t, tc.keyName, foundAPIKey.Name, "Key name should match")
				} else {
					require.Error(t, err, "Should return error for non-existing API key")
					assert.Nil(t, foundAPIKey, "Should not find API key")
				}
			})
		}
	})
}

func (suite *APIKeyRepositoryTestSuite) TestGetByIDAndProfile() {
	testCases := []struct {
		name         string
		profileID    string
		keyName      string
		key          string
		queryProfile string
		shouldFind   bool
	}{
		{
			name:         "Get API key by ID and correct profile",
			profileID:    "test-profile-combo-123",
			keyName:      "Combo Test Key",
			key:          "combo-test-key-123",
			queryProfile: "test-profile-combo-123",
			shouldFind:   true,
		},
		{
			name:         "Get API key by ID and wrong profile",
			profileID:    "test-profile-combo-456",
			keyName:      "Wrong Profile Key",
			key:          "wrong-profile-key-456",
			queryProfile: "wrong-profile-id",
			shouldFind:   false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		apiKeyRepo := repository.NewAPIKeyRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup - create API key first
				apiKey := &models.APIKey{
					BaseModel: frame.BaseModel{
						ID:          util.IDString(),
						TenantID:    "test-tenant",
						PartitionID: "test-partition",
					},
					ProfileID: tc.profileID,
					Name:      tc.keyName,
					Key:       tc.key,
					Scope:     "",
				}

				err := apiKeyRepo.Save(ctx, apiKey)
				require.NoError(t, err)

				// Execute
				foundAPIKey, err := apiKeyRepo.GetByIDAndProfile(ctx, apiKey.ID, tc.queryProfile)

				// Verify
				if tc.shouldFind {
					require.NoError(t, err)
					require.NotNil(t, foundAPIKey, "Should find API key")
					assert.Equal(t, apiKey.ID, foundAPIKey.ID, "API key ID should match")
					assert.Equal(t, tc.profileID, foundAPIKey.ProfileID, "Profile ID should match")
				} else {
					require.Error(t, err, "Should return error for wrong profile")
					assert.Nil(t, foundAPIKey, "Should not find API key")
				}
			})
		}
	})
}

func (suite *APIKeyRepositoryTestSuite) TestGetByKey() {
	testCases := []struct {
		name       string
		profileID  string
		keyName    string
		key        string
		queryKey   string
		shouldFind bool
	}{
		{
			name:       "Get API key by key value",
			profileID:  "test-profile-key-123",
			keyName:    "Key Value Test",
			key:        "unique-key-value-123",
			queryKey:   "unique-key-value-123",
			shouldFind: true,
		},
		{
			name:       "Get API key by non-existing key value",
			profileID:  "test-profile-key-456",
			keyName:    "Another Key Test",
			key:        "another-unique-key-456",
			queryKey:   "non-existing-key",
			shouldFind: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		apiKeyRepo := repository.NewAPIKeyRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup - create API key first
				apiKey := &models.APIKey{
					BaseModel: frame.BaseModel{
						ID:          util.IDString(),
						TenantID:    "test-tenant",
						PartitionID: "test-partition",
					},
					ProfileID: tc.profileID,
					Name:      tc.keyName,
					Key:       tc.key,
					Scope:     "",
				}

				err := apiKeyRepo.Save(ctx, apiKey)
				require.NoError(t, err)

				// Execute
				foundAPIKey, err := apiKeyRepo.GetByKey(ctx, tc.queryKey)

				// Verify
				if tc.shouldFind {
					require.NoError(t, err)
					require.NotNil(t, foundAPIKey, "Should find API key")
					assert.Equal(t, tc.key, foundAPIKey.Key, "Key should match")
					assert.Equal(t, tc.profileID, foundAPIKey.ProfileID, "Profile ID should match")
				} else {
					require.Error(t, err, "Should return error for non-existing key")
					assert.Nil(t, foundAPIKey, "Should not find API key")
				}
			})
		}
	})
}

func (suite *APIKeyRepositoryTestSuite) TestGetByProfileID() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		apiKeyRepo := repository.NewAPIKeyRepository(svc)

		profileID := "test-profile-list-123"

		// Setup - create multiple API keys for the same profile
		apiKeys := []*models.APIKey{
			{
				BaseModel: frame.BaseModel{
					ID:          util.IDString(),
					TenantID:    "test-tenant",
					PartitionID: "test-partition",
				},
				ProfileID: profileID,
				Name:      "First Key",
				Key:       "first-key-123",
				Scope:     "",
			},
			{
				BaseModel: frame.BaseModel{
					ID:          util.IDString(),
					TenantID:    "test-tenant",
					PartitionID: "test-partition",
				},
				ProfileID: profileID,
				Name:      "Second Key",
				Key:       "second-key-123",
				Scope:     "",
			},
		}

		for _, apiKey := range apiKeys {
			err := apiKeyRepo.Save(ctx, apiKey)
			require.NoError(t, err)
		}

		// Execute
		foundAPIKeys, err := apiKeyRepo.GetByProfileID(ctx, profileID)

		// Verify
		require.NoError(t, err)
		require.Len(t, foundAPIKeys, 2, "Should find 2 API keys")

		// Verify all keys belong to the correct profile
		for _, foundKey := range foundAPIKeys {
			assert.Equal(t, profileID, foundKey.ProfileID, "All keys should belong to the correct profile")
		}
	})
}

func (suite *APIKeyRepositoryTestSuite) TestDelete() {
	testCases := []struct {
		name        string
		profileID   string
		keyName     string
		shouldError bool
	}{
		{
			name:        "Delete existing API key",
			profileID:   "test-profile-delete-123",
			keyName:     "Delete Test Key",
			shouldError: false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		apiKeyRepo := repository.NewAPIKeyRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup - create API key first
				apiKey := &models.APIKey{
					BaseModel: frame.BaseModel{
						ID:          util.IDString(),
						TenantID:    "test-tenant",
						PartitionID: "test-partition",
					},
					ProfileID: tc.profileID,
					Name:      tc.keyName,
					Key:       "delete-test-key-123",
					Scope:     "",
				}

				err := apiKeyRepo.Save(ctx, apiKey)
				require.NoError(t, err)

				// Execute
				err = apiKeyRepo.Delete(ctx, apiKey.ID, tc.profileID)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					// Verify API key is deleted (should return error when trying to find it)
					foundAPIKey, err := apiKeyRepo.GetByID(ctx, apiKey.ID)
					require.Error(t, err, "Should return error for deleted API key")
					assert.Nil(t, foundAPIKey, "API key should be deleted")
				}
			})
		}
	})
}

func TestAPIKeyRepository(t *testing.T) {
	suite.Run(t, new(APIKeyRepositoryTestSuite))
}
