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
	"regexp"
	"slices"
	"strings"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	fevents "github.com/pitabwire/frame/v2/events"
	"github.com/pitabwire/frame/v2/security"
	"gorm.io/gorm"
)

var (
	ErrInvalidPermissionManifest = errors.New("invalid permission manifest")
	ErrPermissionManifestOwner   = errors.New("permission manifest identity is not authorized for namespace")
	permissionNamespaceRegexp    = regexp.MustCompile(permissionNamespacePattern) //nolint:gochecknoglobals
	permissionNameRegexp         = regexp.MustCompile(permissionNamePattern)      //nolint:gochecknoglobals
	permissionDomainRegexp       = regexp.MustCompile(permissionDomainPattern)    //nolint:gochecknoglobals
)

const (
	permissionNamespacePattern = "^[a-z][a-z0-9_]{2,99}$"
	permissionNamePattern      = "^[a-z][a-z0-9_]{1,99}$"
	permissionDomainPattern    = "^[a-z][a-z0-9_-]{1,49}$"
)

type PermissionManifest struct {
	Namespace    string
	Domain       string
	Permissions  []string
	RoleBindings map[string][]string
}

type PermissionRegistryDeps struct {
	ServiceNamespaceRepo repository.ServiceNamespaceRepository
	ServiceAccountRepo   repository.ServiceAccountRepository
	PolicyRepo           repository.ServiceAccountAuthorizationPolicyRepository
	PartitionRepo        repository.PartitionRepository
	AccessRepo           repository.AccessRepository
	AccessRoleRepo       repository.AccessRoleRepository
	PartitionRoleRepo    repository.PartitionRoleRepository
	EventsManager        fevents.Manager
	Authorizer           security.Authorizer
}

func RegisterPermissionManifest(
	ctx context.Context,
	deps PermissionRegistryDeps,
	ownerServiceAccountID string,
	manifest PermissionManifest,
) (*repository.ServiceNamespaceRegistration, error) {
	if strings.TrimSpace(ownerServiceAccountID) == "" {
		return nil, errors.New("permission manifest owner service account is required")
	}
	if deps.ServiceNamespaceRepo == nil || deps.ServiceAccountRepo == nil || deps.PolicyRepo == nil ||
		deps.PartitionRepo == nil || deps.AccessRepo == nil || deps.AccessRoleRepo == nil ||
		deps.PartitionRoleRepo == nil || deps.EventsManager == nil || deps.Authorizer == nil {
		return nil, errors.New("permission registry dependencies are incomplete")
	}

	normalised, err := normalizePermissionManifest(manifest)
	if err != nil {
		return nil, err
	}
	if err = validatePermissionManifestOwner(ctx, deps.ServiceAccountRepo, ownerServiceAccountID, normalised.Namespace); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	registration, err := deps.ServiceNamespaceRepo.RegisterOwned(ctx, &models.ServiceNamespace{
		Namespace:    normalised.Namespace,
		Domain:       normalised.Domain,
		Permissions:  data.JSONMap{"values": normalised.Permissions},
		RoleBindings: roleBindingsJSON(normalised.RoleBindings),
		RegisteredAt: &now,
	}, ownerServiceAccountID)
	if err != nil {
		return nil, err
	}
	if !registration.NeedsReconciliation {
		return registration, nil
	}

	if err = EnsureRootAuthorization(ctx, RootAuthorizationDeps{
		AccessRepo:           deps.AccessRepo,
		AccessRoleRepo:       deps.AccessRoleRepo,
		PartitionRoleRepo:    deps.PartitionRoleRepo,
		ServiceNamespaceRepo: deps.ServiceNamespaceRepo,
		Authorizer:           deps.Authorizer,
	}); err != nil {
		return nil, fmt.Errorf("ensure root authorization after namespace registration: %w", err)
	}

	policies, err := deps.PolicyRepo.ListByNamespace(ctx, normalised.Namespace)
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if err = deps.EventsManager.Emit(ctx, events.EventKeyAuthzServiceAccountSync, data.JSONMap{
			"id":         policy.ServiceAccountID,
			"generation": policy.Generation,
			"reason":     "permission_manifest_registered",
		}); err != nil {
			return nil, fmt.Errorf("requeue service-account policy for namespace %s: %w", normalised.Namespace, err)
		}
	}

	if err = ReQueuePartitionsForAuthorizationSync(
		ctx,
		deps.PartitionRepo,
		deps.EventsManager,
		data.NewSearchQuery(),
	); err != nil {
		return nil, fmt.Errorf("requeue partitions after namespace registration: %w", err)
	}
	if err = deps.ServiceNamespaceRepo.MarkReconciled(
		ctx,
		normalised.Namespace,
		ownerServiceAccountID,
		registration.Namespace.Generation,
	); err != nil {
		return nil, err
	}
	registration.NeedsReconciliation = false
	registration.Namespace.ReconciledGeneration = registration.Namespace.Generation
	return registration, nil
}

func validatePermissionManifestOwner(
	ctx context.Context,
	repo repository.ServiceAccountRepository,
	ownerServiceAccountID string,
	namespace string,
) error {
	owner, err := repo.GetByIDPrimary(ctx, ownerServiceAccountID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: service account does not exist", ErrPermissionManifestOwner)
		}
		return fmt.Errorf("load permission manifest owner: %w", err)
	}
	if owner.Type != "internal" || owner.State == int32(commonv1.STATE_DELETED) ||
		owner.PartitionID != authz.RootPartitionID ||
		strings.TrimSpace(owner.Name) != namespace {
		return fmt.Errorf("%w: service account %q cannot own %q", ErrPermissionManifestOwner, owner.Name, namespace)
	}
	return nil
}

func normalizePermissionManifest(manifest PermissionManifest) (PermissionManifest, error) {
	manifest.Namespace = strings.TrimSpace(manifest.Namespace)
	if !permissionNamespaceRegexp.MatchString(manifest.Namespace) {
		return PermissionManifest{}, fmt.Errorf("%w: invalid namespace %q", ErrInvalidPermissionManifest, manifest.Namespace)
	}
	manifest.Domain = strings.TrimSpace(manifest.Domain)
	if manifest.Domain == "" {
		manifest.Domain = models.DomainDefault
	}
	if !permissionDomainRegexp.MatchString(manifest.Domain) {
		return PermissionManifest{}, fmt.Errorf("%w: invalid domain %q", ErrInvalidPermissionManifest, manifest.Domain)
	}

	manifest.Permissions = normalizeStrings(manifest.Permissions)
	if len(manifest.Permissions) == 0 {
		return PermissionManifest{}, fmt.Errorf("%w: at least one permission is required", ErrInvalidPermissionManifest)
	}
	for _, permission := range manifest.Permissions {
		if !permissionNameRegexp.MatchString(permission) {
			return PermissionManifest{}, fmt.Errorf("%w: invalid permission %q", ErrInvalidPermissionManifest, permission)
		}
	}

	bindings := make(map[string][]string, len(manifest.RoleBindings))
	for role, permissions := range manifest.RoleBindings {
		role = strings.TrimSpace(role)
		if !isPermissionManifestRole(role) {
			return PermissionManifest{}, fmt.Errorf("%w: invalid role %q", ErrInvalidPermissionManifest, role)
		}
		permissions = normalizeStrings(permissions)
		for _, permission := range permissions {
			if !slices.Contains(manifest.Permissions, permission) {
				return PermissionManifest{}, fmt.Errorf(
					"%w: role %q references undeclared permission %q",
					ErrInvalidPermissionManifest,
					role,
					permission,
				)
			}
		}
		bindings[role] = permissions
	}
	manifest.RoleBindings = bindings
	return manifest, nil
}

func isPermissionManifestRole(role string) bool {
	switch role {
	case "owner", "admin", "operator", "viewer", "member", "service":
		return true
	default:
		return false
	}
}

func normalizeStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func roleBindingsJSON(bindings map[string][]string) data.JSONMap {
	result := make(data.JSONMap, len(bindings))
	for role, permissions := range bindings {
		result[role] = permissions
	}
	return result
}
