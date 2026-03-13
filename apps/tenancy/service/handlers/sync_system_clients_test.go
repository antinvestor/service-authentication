package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/security"
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
		queryParams         string
		httpMethod          string
		expectedStatus      int
		expectedTriggered   bool
		expectedContentType string
		description         string
	}{
		{
			name:                "sync_triggered",
			queryParams:         "",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should return triggered=true and queue sync jobs",
		},
		{
			name:                "with_count_limit",
			queryParams:         "?count=25",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should respect optional count limit",
		},
		{
			name:                "invalid_count_uses_default",
			queryParams:         "?count=invalid",
			httpMethod:          http.MethodGet,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should sync all records when count is invalid",
		},
		{
			name:                "post_method",
			queryParams:         "",
			httpMethod:          http.MethodPost,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should work with POST method",
		},
		{
			name:                "put_method",
			queryParams:         "",
			httpMethod:          http.MethodPut,
			expectedStatus:      http.StatusOK,
			expectedTriggered:   true,
			expectedContentType: "application/json",
			description:         "Should work with PUT method",
		},
		{
			name:                "delete_method",
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

				ctx, svc, dep := suite.CreateService(t, depOpts)

				// Seed the sync-bot with service role so CanPartitionManage passes.
				suite.SeedTenantRole(ctx, svc, "tenant", "partition", "sync-bot", "service")

				// Create test request
				url := "/_system/sync/clients" + tc.queryParams
				req := httptest.NewRequest(tc.httpMethod, url, nil)
				claims := &security.AuthenticationClaims{
					TenantID:    "tenant",
					PartitionID: "partition",
					Roles:       []string{"system_internal"},
				}
				claims.Subject = "sync-bot"
				req = req.WithContext(claims.ClaimsToContext(ctx))
				rw := httptest.NewRecorder()
				// Call handler
				dep.Server.SynchronizeSystemClients(rw, req)

				// Verify response status and content type
				assert.Equal(t, tc.expectedStatus, rw.Code, tc.description)
				assert.Equal(t, tc.expectedContentType, rw.Header().Get("Content-Type"), tc.expectedContentType)

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

func (suite *SyncPartitionsTestSuite) TestNewSecureRouterV1() {
	suite.T().Run("router_creation", func(t *testing.T) {
		suite.WithTestDependancies(t, func(t *testing.T, dep *definition.DependencyOption) {
			// Create service with test dependencies
			ctx, svc, _ := suite.CreateService(t, dep)

			// Create partition server
			auth := svc.SecurityManager().GetAuthorizer(ctx)
			authzMiddleware := authz.NewMiddleware(auth)
			partitionServer := handlers.NewPartitionServer(ctx, svc, authzMiddleware, auth)

			// Get router
			router := partitionServer.NewSecureRouterV1()

			// Verify router is not nil
			assert.NotNil(t, router)

			// Test that the route is registered by making a request
			req := httptest.NewRequest(http.MethodGet, handlers.SyncClientsHTTPPath, nil)
			req = req.WithContext(ctx)
			rw := httptest.NewRecorder()

			// Call router
			router.ServeHTTP(rw, req)

			// Should not return 404 (route should be found)
			assert.NotEqual(t, http.StatusNotFound, rw.Code)
		})
	})
}

// Authorization is now handled by TenancyAccessMiddleware (Keto ReBAC)
// instead of manual system_internal role checking in the handler.
