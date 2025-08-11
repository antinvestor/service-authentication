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

type LoginRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (suite *LoginRepositoryTestSuite) TestSave() {
	testCases := []struct {
		name         string
		profileHash  string
		passwordHash string
		shouldError  bool
	}{
		{
			name:         "Save new login",
			profileHash:  "test-profile-hash-123",
			passwordHash: "hashed-password-123",
			shouldError:  false,
		},
		{
			name:         "Save login with empty profile hash",
			profileHash:  "",
			passwordHash: "hashed-password-123",
			shouldError:  false, // Repository doesn't validate, just saves
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
					BaseModel: frame.BaseModel{
						ID: util.IDString(),
					},
					ProfileHash:  tc.profileHash,
					PasswordHash: []byte(tc.passwordHash),
				}

				// Execute
				err := loginRepo.Save(ctx, login)

				// Verify
				if tc.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					assert.NotEmpty(t, login.ID, "Login ID should be set")
					assert.Equal(t, tc.profileHash, login.ProfileHash, "Profile hash should match")
					assert.Equal(t, tc.passwordHash, string(login.PasswordHash), "Password hash should match")
				}
			})
		}
	})
}

func (suite *LoginRepositoryTestSuite) TestGetByProfileHash() {
	testCases := []struct {
		name         string
		profileHash  string
		passwordHash string
		queryHash    string
		shouldFind   bool
	}{
		{
			name:         "Get existing login by profile hash",
			profileHash:  "test-profile-hash-456",
			passwordHash: "hashed-password-456",
			queryHash:    "test-profile-hash-456",
			shouldFind:   true,
		},
		{
			name:         "Get non-existing login by profile hash",
			profileHash:  "test-profile-hash-789",
			passwordHash: "hashed-password-789",
			queryHash:    "non-existing-hash",
			shouldFind:   false,
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
					BaseModel: frame.BaseModel{
						ID: util.IDString(),
					},
					ProfileHash:  tc.profileHash,
					PasswordHash: []byte(tc.passwordHash),
				}

				err := loginRepo.Save(ctx, login)
				require.NoError(t, err)

				// Execute
				foundLogin, err := loginRepo.GetByProfileHash(ctx, tc.queryHash)

				// Verify
				require.NoError(t, err)
				if tc.shouldFind {
					require.NotNil(t, foundLogin, "Should find login")
					assert.Equal(t, tc.profileHash, foundLogin.ProfileHash, "Profile hash should match")
					assert.Equal(t, tc.passwordHash, string(foundLogin.PasswordHash), "Password hash should match")
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
		profileHash string
		shouldError bool
	}{
		{
			name:        "Delete existing login",
			profileHash: "test-profile-hash-delete",
			shouldError: false,
		},
		{
			name:        "Delete non-existing login",
			profileHash: "non-existing-profile-hash",
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
					BaseModel: frame.BaseModel{
						ID: util.IDString(),
					},
					ProfileHash:  tc.profileHash,
					PasswordHash: []byte("test-password-hash"),
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
					foundLogin, err := loginRepo.GetByProfileHash(ctx, tc.profileHash)
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
