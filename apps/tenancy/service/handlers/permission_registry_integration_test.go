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
	"time"

	notificationv1 "buf.build/gen/go/antinvestor/notification/protocolbuffers/go/notification/v1"
	"github.com/antinvestor/common/v3/permissions"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/frametests/definition"
	"github.com/pitabwire/frame/v3/security"
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
		// Registration requires an internal service-account principal, not
		// only a service_account_id claim.
		Roles: []string{security.ConstantSystemInternalRole},
		Ext:   map[string]any{"service_account_id": serviceAccountID},
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

// TestLateRegisteredNamespaceGetsRootAdminTuple reproduces a namespace
// (service_notification) registered via /_internal/register/permissions after
// tenancy's setup bootstrap already provisioned the root admin.
func (s *PermissionRegistryTestSuite) TestLateRegisteredNamespaceGetsRootAdminTuple() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, svc, deps := s.CreateService(t, depOpts)
		auth := authz.SerialisedAuthorizer(ctx, svc)

		adminProfileID := s.createRootAccess(ctx, deps, rootAdminRoleID)
		s.Require().NoError(business.EnsureRootAuthorization(ctx, business.RootAuthorizationDeps{
			AccessRepo: deps.AccessRepo, AccessRoleRepo: deps.AccessRoleRepo, PartitionRoleRepo: deps.PartitionRoleRepo,
			ServiceNamespaceRepo: deps.ServiceNamespaceRepo, Authorizer: auth,
		}))

		owner := s.rootServiceAccount(ctx, deps, "service_notification")
		manifest := permissions.BuildManifest(
			notificationv1.File_notification_v1_notification_proto.Services().ByName("NotificationService"))
		response := invokePermissionRegistration(serviceAccountContext(ctx, owner.GetID()),
			deps.Server.NewPermissionRegistrationHandler(), map[string]any{
				"namespace": manifest.Namespace, "permissions": manifest.Permissions, "role_bindings": manifest.RoleBindings,
			})
		s.Require().Equal(http.StatusOK, response.Code, response.Body.String())

		s.True(hasTuple(ctx, t, auth, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: "service_notification", ID: authz.RootTenantID + "/" + authz.RootPartitionID},
			Relation: authz.RoleAdmin,
			Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: adminProfileID},
		}), "late-registered namespace must carry the root admin tuple")

		// Pending SA policies granting the new namespace are re-queued at
		// registration time and materialised by the runtime consumer.
		policies, err := deps.AuthorizationPolicyRepo.ListByNamespace(ctx, "service_notification")
		s.Require().NoError(err)
		s.Require().NotEmpty(policies, "seed must hold policies granting service_notification")
		check := s.firstGrantCheck(ctx, deps, policies[0].ServiceAccountID, "service_notification")
		s.Require().Eventually(func() bool {
			result, checkErr := auth.Check(ctx, check)
			return checkErr == nil && result.Allowed
		}, 30*time.Second, 200*time.Millisecond, "pending service_notification grant must materialise after registration")
	})
}

// firstGrantCheck builds a Keto check for the first permission the service
// account's policy grants in namespace, on the account's own partition.
func (s *PermissionRegistryTestSuite) firstGrantCheck(
	ctx context.Context,
	deps *tests.DepsBuilder,
	serviceAccountID string,
	namespace string,
) security.CheckRequest {
	account, err := deps.ServiceAccountRepo.GetByIDPrimary(ctx, serviceAccountID)
	s.Require().NoError(err)
	state, err := deps.AuthorizationPolicyRepo.GetByServiceAccountID(ctx, serviceAccountID)
	s.Require().NoError(err)
	for _, grant := range state.Grants {
		if grant.Namespace == namespace && len(grant.Permissions) > 0 {
			return security.CheckRequest{
				Object:     security.ObjectRef{Namespace: namespace, ID: account.TenantID + "/" + account.PartitionID},
				Permission: grant.Permissions[0],
				Subject:    security.SubjectRef{Namespace: authz.NamespaceProfile, ID: account.ProfileID},
			}
		}
	}
	s.FailNow("policy has no grant in namespace", namespace)
	return security.CheckRequest{}
}

// rootAdminRoleID is the seeded "admin" partition role on the root partition.
const rootAdminRoleID = "d7j42dspf2tfev9jfgt0"

func (s *PermissionRegistryTestSuite) createRootAccess(ctx context.Context, deps *tests.DepsBuilder, roleID string) string {
	profileID := util.IDString()
	access := &models.Access{
		ProfileID: profileID,
		BaseModel: data.BaseModel{TenantID: authz.RootTenantID, PartitionID: authz.RootPartitionID},
	}
	s.Require().NoError(deps.AccessRepo.Create(ctx, access))
	s.Require().NoError(deps.AccessRoleRepo.Create(ctx, &models.AccessRole{
		AccessID:        access.GetID(),
		PartitionRoleID: roleID,
		BaseModel:       data.BaseModel{TenantID: authz.RootTenantID, PartitionID: authz.RootPartitionID},
	}))
	return profileID
}

func (s *PermissionRegistryTestSuite) rootServiceAccount(
	ctx context.Context,
	deps *tests.DepsBuilder,
	name string,
) *models.ServiceAccount {
	accounts, err := deps.ServiceAccountRepo.ListByPartition(ctx, authz.RootPartitionID)
	s.Require().NoError(err)
	for _, account := range accounts {
		if account.Name == name {
			return account
		}
	}
	s.FailNow("seeded root service account not found", name)
	return nil
}

func hasTuple(ctx context.Context, t *testing.T, auth security.Authorizer, want security.RelationTuple) bool {
	t.Helper()
	stored, err := auth.ListRelations(ctx, want.Object)
	if err != nil {
		t.Fatalf("list relations for %s:%s: %v", want.Object.Namespace, want.Object.ID, err)
	}
	return slices.Contains(stored, want)
}
