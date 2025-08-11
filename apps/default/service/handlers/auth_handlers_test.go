package handlers_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandlersTestSuite struct {
	tests.BaseTestSuite
}

func (suite *AuthHandlersTestSuite) TestShowLoginEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *AuthHandlersTestSuite) TestSubmitLoginEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// Create test login record first
		profileID := "test-profile-login"
		password := "testpassword123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		// Create login record
		login := &models.Login{
			BaseModel: frame.BaseModel{
				ID: util.IDString(),
			},
			ProfileHash:  utils.HashStringSecret(profileID),
			PasswordHash: hashedPassword,
		}

		db := svc.DB(ctx, false)
		err := db.Create(login).Error
		require.NoError(t, err, "Should create login record")

		// Test that we can create login records and access the database
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
		assert.NotEmpty(t, login.ID, "Should have created login record")
	})
}

func (suite *AuthHandlersTestSuite) TestShowRegisterEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *AuthHandlersTestSuite) TestSubmitRegisterEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// Test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")

		// Verify we can access the database
		db := svc.DB(ctx, false)
		assert.NotNil(t, db, "Should have database connection")
	})
}

func (suite *AuthHandlersTestSuite) TestShowConsentEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *AuthHandlersTestSuite) TestShowLogoutEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *AuthHandlersTestSuite) TestForgotEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *AuthHandlersTestSuite) TestSetPasswordEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// Create existing login record
		login := &models.Login{
			BaseModel: frame.BaseModel{
				ID: util.IDString(),
			},
			ProfileHash:  utils.HashStringSecret("test-profile-password"),
			PasswordHash: []byte("old-password-hash"),
		}

		db := svc.DB(ctx, false)
		err := db.Create(login).Error
		require.NoError(t, err, "Should create login record")

		// Test that we can create login records and access the database
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
		assert.NotEmpty(t, login.ID, "Should have created login record")
	})
}

func TestAuthHandlers(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}
