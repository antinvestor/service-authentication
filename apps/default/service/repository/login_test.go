package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type LoginRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (suite *LoginRepositoryTestSuite) TestSave() {
	testCases := []struct {
		name        string
		profileID   string
		source      string
		shouldError bool
	}{
		{
			name:        "Save new login",
			profileID:   "test-profile-id-123",
			source:      "direct",
			shouldError: false,
		},
		{
			name:        "Save login with empty profile ID",
			profileID:   "",
			source:      "direct",
			shouldError: false, // Repository doesn't validate, just saves
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		loginRepo := repository.NewLoginRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup
				login := &models.Login{
					ProfileID: tc.profileID,
					Source:    tc.source,
				}

				// Execute
				err := loginRepo.Save(ctx, login)

				// Assert
				if tc.shouldError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.NotEmpty(t, login.ID)
					assert.Equal(t, tc.profileID, login.ProfileID)
					assert.Equal(t, tc.source, login.Source)
				}
			})
		}
	})
}

func (suite *LoginRepositoryTestSuite) TestGetByProfileID() {
	testCases := []struct {
		name        string
		profileID   string
		source      string
		queryID     string
		shouldFind  bool
	}{
		{
			name:        "Get existing login by profile ID",
			profileID:   "test-profile-id-456",
			source:      "direct",
			queryID:     "test-profile-id-456",
			shouldFind:  true,
		},
		{
			name:        "Get non-existing login by profile ID",
			profileID:   "test-profile-id-789",
			source:      "direct",
			queryID:     "non-existing-id",
			shouldFind:  false,
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		loginRepo := repository.NewLoginRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup - create login first
				login := &models.Login{
					ProfileID: tc.profileID,
					Source:    tc.source,
				}

				err := loginRepo.Save(ctx, login)
				require.NoError(t, err)

				// Execute
				foundLogin, err := loginRepo.GetByProfileID(ctx, tc.queryID)

				// Verify
				require.NoError(t, err)
				if tc.shouldFind {
					require.NotNil(t, foundLogin, "Should find login")
					assert.Equal(t, tc.profileID, foundLogin.ProfileID, "Profile ID should match")
					assert.Equal(t, tc.source, foundLogin.Source, "Source should match")
				} else {
					assert.Nil(t, foundLogin, "Should not find login")
				}
			})
		}
	})
}

func (suite *LoginRepositoryTestSuite) TestDelete() {
	testCases := []struct {
		name        string
		profileID   string
		shouldError bool
	}{
		{
			name:        "Delete existing login",
			profileID:   "test-profile-id-delete",
			shouldError: false,
		},
		{
			name:        "Delete non-existing login",
			profileID:   "non-existing-profile-id",
			shouldError: false, // GORM doesn't error on delete of non-existing record
		},
	}

	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		authSrv, ctx := suite.CreateService(t, dep)
		svc := authSrv.Service()
		loginRepo := repository.NewLoginRepository(svc)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Setup - create login first for valid test case
				login := &models.Login{
					ProfileID: tc.profileID,
					Source:    "direct",
				}

				if tc.name == "Delete existing login" {
					err := loginRepo.Save(ctx, login)
					require.NoError(t, err)
				}

				// Execute
				err := loginRepo.Delete(ctx, login.ID)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)

					// Verify login is deleted
					foundLogin, err := loginRepo.GetByProfileID(ctx, tc.profileID)
					require.NoError(t, err)
					assert.Nil(t, foundLogin, "Login should be deleted")
				}
			})
		}
	})
}

func TestLoginRepository(t *testing.T) {
	suite.Run(t, new(LoginRepositoryTestSuite))
}
