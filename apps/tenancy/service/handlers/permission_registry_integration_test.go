// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
)

type PermissionRegistryTestSuite struct {
	tests.BaseTestSuite
}

func TestPermissionRegistryTestSuite(t *testing.T) {
	suite.Run(t, new(PermissionRegistryTestSuite))
}

func (s *PermissionRegistryTestSuite) TestRegistrationIsAuthenticatedOwnerBoundAndAdditive() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, depOpts)
		handler := deps.Server.NewPermissionRegistrationHandler()
		namespace := "service_dynamic_registry"

		response := invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace": namespace, "permissions": []string{"record_view"}, "role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusForbidden, response.Code)

		ownerID := util.IDString()
		otherOwnerID := util.IDString()
		for _, id := range []string{ownerID, otherOwnerID} {
			err := deps.ServiceAccountRepo.Create(ctx, &models.ServiceAccount{
				Name:      namespace,
				ProfileID: util.IDString(),
				ClientID:  util.IDString(),
				Type:      "internal",
				BaseModel: data.BaseModel{
					ID:          id,
					TenantID:    authz.RootTenantID,
					PartitionID: authz.RootPartitionID,
				},
			})
			s.Require().NoError(err)
		}
		wrongNamespaceID := util.IDString()
		err := deps.ServiceAccountRepo.Create(ctx, &models.ServiceAccount{
			Name:      "service_other",
			ProfileID: util.IDString(),
			ClientID:  util.IDString(),
			Type:      "internal",
			BaseModel: data.BaseModel{
				ID:          wrongNamespaceID,
				TenantID:    authz.RootTenantID,
				PartitionID: authz.RootPartitionID,
			},
		})
		s.Require().NoError(err)
		response = invokePermissionRegistration(serviceAccountContext(ctx, wrongNamespaceID), handler, map[string]any{
			"namespace": namespace, "permissions": []string{"record_view"}, "role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusForbidden, response.Code)
		tenantOwnerID := util.IDString()
		err = deps.ServiceAccountRepo.Create(ctx, &models.ServiceAccount{
			Name:      namespace,
			ProfileID: util.IDString(),
			ClientID:  util.IDString(),
			Type:      "internal",
			BaseModel: data.BaseModel{
				ID:          tenantOwnerID,
				TenantID:    util.IDString(),
				PartitionID: util.IDString(),
			},
		})
		s.Require().NoError(err)
		response = invokePermissionRegistration(serviceAccountContext(ctx, tenantOwnerID), handler, map[string]any{
			"namespace": namespace, "permissions": []string{"record_view"}, "role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusForbidden, response.Code)

		ctx = serviceAccountContext(ctx, ownerID)
		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace": namespace, "permissions": []string{"record_view"}, "role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusOK, response.Code, response.Body.String())

		registered, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, namespace)
		s.Require().NoError(err)
		s.Equal(ownerID, registered.OwnerServiceAccountID)
		s.Equal(int64(1), registered.Generation)
		s.Equal(int64(1), registered.ReconciledGeneration)

		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace":     namespace,
			"permissions":   []string{"record_manage", "record_view"},
			"role_bindings": map[string][]string{"service": {"record_manage", "record_view"}},
		})
		s.Equal(http.StatusOK, response.Code, response.Body.String())
		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace":     namespace,
			"permissions":   []string{"record_manage", "record_view"},
			"role_bindings": map[string][]string{"service": {"record_manage", "record_view"}},
		})
		s.Equal(http.StatusOK, response.Code, response.Body.String())
		registered, err = deps.ServiceNamespaceRepo.GetByNamespace(ctx, namespace)
		s.Require().NoError(err)
		s.Equal(int64(2), registered.Generation)
		s.Equal(int64(2), registered.ReconciledGeneration)
		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace":     namespace,
			"domain":        "other",
			"permissions":   []string{"record_manage", "record_view"},
			"role_bindings": map[string][]string{"service": {"record_manage", "record_view"}},
		})
		s.Equal(http.StatusConflict, response.Code)

		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace":     namespace,
			"permissions":   []string{"record_manage", "record_view"},
			"role_bindings": map[string][]string{"service": {"record_view"}},
		})
		s.Equal(http.StatusConflict, response.Code)

		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace": namespace, "permissions": []string{"record_manage"}, "role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusConflict, response.Code)

		response = invokePermissionRegistration(serviceAccountContext(ctx, otherOwnerID), handler, map[string]any{
			"namespace":     namespace,
			"permissions":   []string{"record_manage", "record_view"},
			"role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusConflict, response.Code)

		response = invokePermissionRegistration(ctx, handler, map[string]any{
			"namespace": namespace, "permissions": []string{"*"}, "role_bindings": map[string][]string{},
		})
		s.Equal(http.StatusBadRequest, response.Code)
	})
}

func (s *PermissionRegistryTestSuite) TestConcurrentRegistrationHasOneOwner() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, depOpts)
		handler := deps.Server.NewPermissionRegistrationHandler()
		namespace := "service_concurrent_registry"
		ownerIDs := []string{util.IDString(), util.IDString()}
		for _, id := range ownerIDs {
			err := deps.ServiceAccountRepo.Create(ctx, &models.ServiceAccount{
				Name:      namespace,
				ProfileID: util.IDString(),
				ClientID:  util.IDString(),
				Type:      "internal",
				BaseModel: data.BaseModel{
					ID:          id,
					TenantID:    authz.RootTenantID,
					PartitionID: authz.RootPartitionID,
				},
			})
			s.Require().NoError(err)
		}

		statuses := make([]int, len(ownerIDs))
		var wait sync.WaitGroup
		wait.Add(len(ownerIDs))
		for index, ownerID := range ownerIDs {
			go func() {
				defer wait.Done()
				response := invokePermissionRegistration(serviceAccountContext(ctx, ownerID), handler, map[string]any{
					"namespace":     namespace,
					"permissions":   []string{"record_view"},
					"role_bindings": map[string][]string{},
				})
				statuses[index] = response.Code
			}()
		}
		wait.Wait()
		slices.Sort(statuses)
		s.Equal([]int{http.StatusOK, http.StatusConflict}, statuses)

		registered, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, namespace)
		s.Require().NoError(err)
		s.Contains(ownerIDs, registered.OwnerServiceAccountID)
	})
}

func serviceAccountContext(ctx context.Context, serviceAccountID string) context.Context {
	claims := &security.AuthenticationClaims{
		Ext: map[string]any{"service_account_id": serviceAccountID},
	}
	claims.Subject = util.IDString()
	return claims.ClaimsToContext(ctx)
}

func invokePermissionRegistration(
	ctx context.Context,
	handler http.Handler,
	manifest map[string]any,
) *httptest.ResponseRecorder {
	body, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/_internal/register/permissions", bytes.NewReader(body)).WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
