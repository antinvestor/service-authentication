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

package business

import (
	"context"
	"errors"
	"fmt"
	"slices"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	tenancyv2 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v2"
	"github.com/antinvestor/common/v3/permissions"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v3/security"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gorm.io/gorm"
)

// SetupBootstrapDeps bundles what the tenancy setup Job's bootstrap step needs.
type SetupBootstrapDeps struct {
	Registry         PermissionRegistryDeps
	AuthContractRepo repository.AuthContractRepository
	// PermissionDescriptors are tenancy's own Connect service descriptors. They
	// must all declare the service_tenancy namespace.
	PermissionDescriptors []protoreflect.ServiceDescriptor
}

// TenancyPermissionDescriptors are tenancy's Connect services whose
// permission manifests together make up the service_tenancy namespace.
func TenancyPermissionDescriptors() []protoreflect.ServiceDescriptor {
	return []protoreflect.ServiceDescriptor{
		tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService"),
		tenancyv2.File_tenancy_v2_auth_contract_proto.Services().ByName("AuthContractService"),
	}
}

// RunSetupBootstrap is the tenancy setup Job's bootstrap step:
//
//  1. register tenancy's own permission manifest (service_tenancy) locally —
//     tenancy is the registration target, so it cannot publish to itself;
//  2. write root super-user tuples for every registered namespace;
//  3. write service-bot Plane-1 tenancy access;
//  4. materialise pending SA policies whose namespaces are now registered.
//
// Step 1 must precede step 4: seeded SA policies granting service_tenancy
// permissions otherwise stay failed with "namespace is not registered".
// Every step is idempotent, so re-running the Job is the recovery path.
func RunSetupBootstrap(ctx context.Context, deps SetupBootstrapDeps) error {
	registry := deps.Registry
	// Setup never calls Service.Run, so queue publishers are not initialised;
	// step 4 reconciles synchronously instead of re-queueing events.
	registry.DeferPolicyReconciliation = true
	if err := RegisterTenancyPermissionManifest(ctx, registry, deps.PermissionDescriptors...); err != nil {
		return fmt.Errorf("setup bootstrap: register tenancy permission manifest: %w", err)
	}

	if err := EnsureRootAuthorization(ctx, RootAuthorizationDeps{
		AccessRepo:           registry.AccessRepo,
		AccessRoleRepo:       registry.AccessRoleRepo,
		PartitionRoleRepo:    registry.PartitionRoleRepo,
		ServiceNamespaceRepo: registry.ServiceNamespaceRepo,
		Authorizer:           registry.Authorizer,
	}); err != nil {
		return err
	}
	if err := EnsureServiceBotTenancyAccess(ctx, ServiceBotTenancyDeps{
		ServiceAccountRepo: registry.ServiceAccountRepo,
		PartitionRepo:      registry.PartitionRepo,
		Authorizer:         registry.Authorizer,
	}); err != nil {
		return err
	}

	// Policies whose namespaces are still missing stay pending until that
	// service's setup Job registers its manifest and re-queues them.
	reconciler := events.NewAuthzServiceAccountSyncEventHandler(
		registry.ServiceAccountRepo,
		registry.PartitionRepo,
		registry.PolicyRepo,
		registry.ServiceNamespaceRepo,
		deps.AuthContractRepo,
		registry.EventsManager,
		registry.Authorizer,
	)
	if err := reconciler.ReconcilePending(ctx); err != nil {
		return fmt.Errorf("setup bootstrap: reconcile pending SA policies: %w", err)
	}
	return nil
}

// RegisterTenancyPermissionManifest registers tenancy's own permission
// namespace through the same business path that serves
// /_internal/register/permissions, owned by tenancy's root service account.
func RegisterTenancyPermissionManifest(
	ctx context.Context,
	deps PermissionRegistryDeps,
	sds ...protoreflect.ServiceDescriptor,
) error {
	manifest, err := mergeServiceManifests(authz.NamespaceTenancy, sds)
	if err != nil {
		return err
	}
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	ownerID, err := resolveNamespaceOwner(ctx, deps, manifest.Namespace)
	if err != nil {
		return err
	}
	_, err = RegisterPermissionManifest(ctx, deps, ownerID, manifest)
	return err
}

// mergeServiceManifests unions the permission manifests of several Connect
// services that share one namespace (tenancy v1 and the v2 auth contract).
func mergeServiceManifests(namespace string, sds []protoreflect.ServiceDescriptor) (PermissionManifest, error) {
	merged := PermissionManifest{Namespace: namespace, RoleBindings: map[string][]string{}}
	for _, sd := range sds {
		if sd == nil {
			continue
		}
		manifest := permissions.BuildManifest(sd)
		if manifest.Namespace != namespace {
			return PermissionManifest{}, fmt.Errorf(
				"%w: service %s declares namespace %q, expected %q",
				ErrInvalidPermissionManifest, sd.FullName(), manifest.Namespace, namespace,
			)
		}
		merged.Permissions = append(merged.Permissions, manifest.Permissions...)
		for role, perms := range manifest.RoleBindings {
			merged.RoleBindings[role] = append(merged.RoleBindings[role], perms...)
		}
	}
	if len(merged.Permissions) == 0 {
		return PermissionManifest{}, fmt.Errorf("%w: no permissions declared for %q", ErrInvalidPermissionManifest, namespace)
	}
	return merged, nil
}

// resolveNamespaceOwner returns the service account that owns namespace: the
// recorded owner when already registered, otherwise the single live internal
// root-partition service account whose name or client id matches it.
func resolveNamespaceOwner(ctx context.Context, deps PermissionRegistryDeps, namespace string) (string, error) {
	existing, err := deps.ServiceNamespaceRepo.GetByNamespace(ctx, namespace)
	if err == nil {
		return existing.OwnerServiceAccountID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("load %s registration: %w", namespace, err)
	}

	accounts, err := deps.ServiceAccountRepo.ListByPartition(ctx, authz.RootPartitionID)
	if err != nil {
		return "", fmt.Errorf("list root service accounts: %w", err)
	}
	var owners []string
	for _, account := range accounts {
		if account.Type == "internal" && account.State != int32(commonv1.STATE_DELETED) &&
			serviceAccountOwnsNamespace(account, namespace) {
			owners = append(owners, account.GetID())
		}
	}
	slices.Sort(owners)
	switch len(owners) {
	case 0:
		return "", fmt.Errorf("%w: no root service account owns %q", ErrPermissionManifestOwner, namespace)
	case 1:
		return owners[0], nil
	default:
		return "", fmt.Errorf("%w: %d root service accounts claim %q: %v",
			ErrPermissionManifestOwner, len(owners), namespace, owners)
	}
}
