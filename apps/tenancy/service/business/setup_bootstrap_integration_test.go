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

package business_test

import (
	"context"
	"slices"
	"testing"

	notificationv1 "buf.build/gen/go/antinvestor/notification/protocolbuffers/go/notification/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/v3"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/frametests/definition"
	"github.com/pitabwire/frame/v3/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gorm.io/gorm"
)

const (
	// Seeded root-partition identities (migrations/0001/20260704_01_greenfield_seed.sql).
	seededTenancyServiceAccountID      = "c2f4j7au6s7f91uqnosg"
	seededNotificationProfileID        = "d75qclkpf2t1uum8ij5g"
	seededNotificationServiceAccountID = "c2f4j7au6s7f91uqnoug"
	seededRootAdminRoleID              = "d7j42dspf2tfev9jfgt0"
)

var rootPath = authz.RootTenantID + "/" + authz.RootPartitionID //nolint:gochecknoglobals // test constant

// SetupBootstrapTestSuite runs the tenancy setup bootstrap against a freshly
// migrated database on which service_tenancy has never been registered.
type SetupBootstrapTestSuite struct {
	tests.BaseTestSuite
}

func TestSetupBootstrapTestSuite(t *testing.T) {
	s := new(SetupBootstrapTestSuite)
	s.UnregisteredTenancyNamespace = true
	suite.Run(t, s)
}

func (s *SetupBootstrapTestSuite) bootstrapDeps(
	svc *frame.Service,
	deps *tests.DepsBuilder,
	auth security.Authorizer,
) business.SetupBootstrapDeps {
	return business.SetupBootstrapDeps{
		Registry:              tests.SetupRegistryDeps(svc, deps.Server, auth),
		AuthContractRepo:      deps.AuthContractRepo,
		PermissionDescriptors: business.TenancyPermissionDescriptors(),
	}
}

func (s *SetupBootstrapTestSuite) TestRunSetupBootstrap_RegistersTenancyNamespaceOnFreshDatabase() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, svc, deps := s.CreateService(t, depOpts)
		auth := authz.SerialisedAuthorizer(ctx, svc)

		_, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, authz.NamespaceTenancy)
		s.Require().ErrorIs(err, gorm.ErrRecordNotFound, "fresh database must not carry service_tenancy yet")

		s.Require().NoError(business.RunSetupBootstrap(ctx, s.bootstrapDeps(svc, deps, auth)))

		registered, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, authz.NamespaceTenancy)
		s.Require().NoError(err)
		s.Equal(seededTenancyServiceAccountID, registered.OwnerServiceAccountID)
		s.Equal(int64(1), registered.Generation)
		s.Equal(registered.Generation, registered.ReconciledGeneration)

		permissions := stringValues(registered.Permissions["values"])
		for _, want := range []string{"partition_view", "tenant_view", "client_manage", "service_account_manage"} {
			s.Contains(permissions, want)
		}
		for _, role := range []string{authz.RoleOwner, authz.RoleAdmin, authz.RoleMember} {
			s.Contains(registered.RoleBindings, role)
		}
	})
}

// The live failure: service-notification calling GetPartition is denied
// partition_view on service_tenancy because its seeded policy never
// materialised. The same setup run must register and then reconcile it.
func (s *SetupBootstrapTestSuite) TestRunSetupBootstrap_MaterialisesPendingTenancyGrants() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, svc, deps := s.CreateService(t, depOpts)
		auth := authz.SerialisedAuthorizer(ctx, svc)
		check := security.CheckRequest{
			Object:     security.ObjectRef{Namespace: authz.NamespaceTenancy, ID: rootPath},
			Permission: "partition_view",
			Subject:    security.SubjectRef{Namespace: authz.NamespaceProfile, ID: seededNotificationProfileID},
		}

		s.Require().NoError(business.RunSetupBootstrap(ctx, s.bootstrapDeps(svc, deps, auth)))

		// Keto is shared across the suite, so the policy record (per-test
		// database) is the authoritative "was it reconciled here" signal.
		state, err := deps.AuthorizationPolicyRepo.GetByServiceAccountID(ctx, seededNotificationServiceAccountID)
		s.Require().NoError(err)
		s.NotContains(state.Policy.LastError, `"service_tenancy" is not registered`)
		s.Contains(state.Policy.LastError, `"service_setting" is not registered`,
			"grants in still-unregistered namespaces stay pending")

		after, err := auth.Check(ctx, check)
		s.Require().NoError(err)
		s.True(after.Allowed, "service_notification must hold partition_view on service_tenancy after setup")
	})
}

func (s *SetupBootstrapTestSuite) TestRunSetupBootstrap_IsIdempotent() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, svc, deps := s.CreateService(t, depOpts)
		auth := authz.SerialisedAuthorizer(ctx, svc)
		adminProfileID := createRootAccess(ctx, s, deps, seededRootAdminRoleID)
		bootstrap := s.bootstrapDeps(svc, deps, auth)

		s.Require().NoError(business.RunSetupBootstrap(ctx, bootstrap))
		s.Require().NoError(business.RunSetupBootstrap(ctx, bootstrap))

		registered, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, authz.NamespaceTenancy)
		s.Require().NoError(err)
		s.Equal(int64(1), registered.Generation, "an unchanged manifest must not bump the generation")
		s.Equal(int64(1), registered.ReconciledGeneration)

		adminTuple := security.RelationTuple{
			Object:   security.ObjectRef{Namespace: authz.NamespaceTenancy, ID: rootPath},
			Relation: authz.RoleAdmin,
			Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: adminProfileID},
		}
		stored, err := auth.ListRelations(ctx, adminTuple.Object)
		s.Require().NoError(err)
		s.Equal(1, countTuple(stored, adminTuple), "root admin tuple must be written exactly once")
	})
}

func (s *SetupBootstrapTestSuite) TestRegisterTenancyPermissionManifest_RejectsInvalidInput() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, svc, deps := s.CreateService(t, depOpts)
		registry := tests.SetupRegistryDeps(svc, deps.Server, authz.SerialisedAuthorizer(ctx, svc))

		testCases := []struct {
			name    string
			sds     []protoreflect.ServiceDescriptor
			wantErr error
		}{
			{
				name:    "foreign namespace descriptor",
				sds:     []protoreflect.ServiceDescriptor{notificationv1.File_notification_v1_notification_proto.Services().ByName("NotificationService")},
				wantErr: business.ErrInvalidPermissionManifest,
			},
			{
				name:    "no descriptors",
				sds:     nil,
				wantErr: business.ErrInvalidPermissionManifest,
			},
		}
		for _, tc := range testCases {
			s.Run(tc.name, func() {
				err := business.RegisterTenancyPermissionManifest(ctx, registry, tc.sds...)
				s.Require().ErrorIs(err, tc.wantErr)
			})
		}

		_, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, authz.NamespaceTenancy)
		s.Require().ErrorIs(err, gorm.ErrRecordNotFound, "rejected manifests must not register anything")
	})
}

func (s *SetupBootstrapTestSuite) TestRegisterTenancyPermissionManifest_RequiresOwningServiceAccount() {
	s.WithTestDependancies(s.T(), func(t *testing.T, depOpts *definition.DependencyOption) {
		ctx, svc, deps := s.CreateService(t, depOpts)
		registry := tests.SetupRegistryDeps(svc, deps.Server, authz.SerialisedAuthorizer(ctx, svc))

		owner, err := deps.ServiceAccountRepo.GetByIDPrimary(ctx, seededTenancyServiceAccountID)
		s.Require().NoError(err)
		s.Require().NoError(deps.ServiceAccountRepo.Delete(ctx, owner.GetID()))

		err = business.RegisterTenancyPermissionManifest(ctx, registry, business.TenancyPermissionDescriptors()...)
		s.Require().ErrorIs(err, business.ErrPermissionManifestOwner)
	})
}

func createRootAccess(ctx context.Context, s *SetupBootstrapTestSuite, deps *tests.DepsBuilder, roleID string) string {
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

func countTuple(stored []security.RelationTuple, want security.RelationTuple) int {
	count := 0
	for _, tuple := range stored {
		if tuple == want {
			count++
		}
	}
	return count
}

func stringValues(raw any) []string {
	values, _ := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	slices.Sort(result)
	return result
}
