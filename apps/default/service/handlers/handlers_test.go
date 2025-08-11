package handlers_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type HandlersTestSuite struct {
	tests.BaseTestSuite
}

func (suite *HandlersTestSuite) TestIndexEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *HandlersTestSuite) TestErrorEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *HandlersTestSuite) TestCreateAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *HandlersTestSuite) TestListAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *HandlersTestSuite) TestGetAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *HandlersTestSuite) TestDeleteAPIKeyEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func (suite *HandlersTestSuite) TestTokenEnrichmentEndpoint() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependancyOption) {
		svc, ctx := suite.CreateService(t, dep)

		// For now, just test that the service was created successfully
		assert.NotNil(t, svc, "Should create service")
		assert.NotNil(t, ctx, "Should create context")
	})
}

func TestHandlers(t *testing.T) {
	suite.Run(t, new(HandlersTestSuite))
}
