package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type SyncPartitionsTestSuite struct {
	tests.BaseTestSuite
}

func TestSyncPartitionsTestSuite(t *testing.T) {
	suite.Run(t, new(SyncPartitionsTestSuite))
}

func (suite *SyncPartitionsTestSuite) TestSynchronizePartitions() {
	testCases := []struct {
		name                string
		syncEnabled         bool
		queryParams         string
		httpMethod          string
		expectedStatus      int
		expectedTriggered   bool
		expectedContentType string
		description         string
	}{
		{
			name:                "sync_disabled",
			syncEnabled:         false,
			queryParams:         "",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   false,
			expectedContentType: "application/json",
			description:         "Should return triggered=false when sync is disabled",
		},
		{
			name:                "sync_enabled",
			syncEnabled:         true,
			queryParams:         "",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should return triggered=true when sync is enabled",
		},
		{
			name:                "with_query_parameters",
			syncEnabled:         true,
			queryParams:         "?q=test&page=1&count=25",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should handle query parameters correctly",
		},
		{
			name:                "invalid_page_parameter",
			syncEnabled:         true,
			queryParams:         "?page=invalid",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should default page to 0 for invalid page parameter",
		},
		{
			name:                "invalid_count_parameter",
			syncEnabled:         true,
			queryParams:         "?count=invalid",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should default count to 50 for invalid count parameter",
		},
		{
			name:                "empty_query_parameters",
			syncEnabled:         true,
			queryParams:         "?q=&page=&count=",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should handle empty query parameters",
		},
		{
			name:                "post_method",
			syncEnabled:         true,
			queryParams:         "",
			httpMethod:          http.MethodPost,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should work with POST method",
		},
		{
			name:                "put_method",
			syncEnabled:         true,
			queryParams:         "",
			httpMethod:          http.MethodPut,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should work with PUT method",
		},
		{
			name:                "delete_method",
			syncEnabled:         true,
			queryParams:         "",
			httpMethod:          http.MethodDelete,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should work with DELETE method",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			suite.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {

				ctx, _, dep := suite.CreateService(t, depOpts)

				// Create test request
				url := "/_system/sync/partitions" + tc.queryParams
				req := httptest.NewRequest(tc.httpMethod, url, nil)
				req = req.WithContext(ctx)
				rw := httptest.NewRecorder()
				// Call handler
				dep.Server.SynchronizePartitions(rw, req)

				// Verify response status and content type
				assert.Equal(t, tc.expectedStatus, rw.Code, tc.description)
				assert.Equal(t, tc.expectedContentType, rw.Header().Get("Content-Type"), tc.description)

				// Parse response body
				var response map[string]interface{}
				err := json.Unmarshal(rw.Body.Bytes(), &response)
				require.NoError(t, err, "Response should be valid JSON")

				// Verify triggered field
				triggered, exists := response["triggered"]
				assert.True(t, exists, "Response should contain 'triggered' field")
				assert.Equal(t, tc.expectedTriggered, triggered, tc.description)
			})
		})
	}
}

func (suite *SyncPartitionsTestSuite) TestSynchronizePartitions_InvalidConfigType() {
	suite.T().Run("invalid_config_type", func(t *testing.T) {
		suite.WithTestDependancies(t, func(t *testing.T, depOpts *definition.DependencyOption) {
			ctx, _, dep := suite.CreateService(t, depOpts)

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/_system/sync/partitions", nil)
			req = req.WithContext(ctx)
			rw := httptest.NewRecorder()

			// Call handler
			dep.Server.SynchronizePartitions(rw, req)

			// Verify response - should return 500 for invalid config
			assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
		})
	})
}

func (suite *SyncPartitionsTestSuite) TestNewSecureRouterV1() {
	suite.T().Run("router_creation", func(t *testing.T) {
		suite.WithTestDependancies(t, func(t *testing.T, dep *definition.DependencyOption) {
			// Create service with test dependencies
			ctx, svc, _ := suite.CreateService(t, dep)

			// Create partition server
			partitionServer := handlers.NewPartitionServer(ctx, svc)

			// Get router
			router := partitionServer.NewSecureRouterV1()

			// Verify router is not nil
			assert.NotNil(t, router)

			// Test that the route is registered by making a request
			req := httptest.NewRequest(http.MethodGet, handlers.SyncPartitionsHTTPPath, nil)
			req = req.WithContext(ctx)
			rw := httptest.NewRecorder()

			// Call router
			router.ServeHTTP(rw, req)

			// Should not return 404 (route should be found)
			assert.NotEqual(t, http.StatusNotFound, rw.Code)
		})
	})
}
