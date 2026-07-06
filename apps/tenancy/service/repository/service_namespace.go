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

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/workerpool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrServiceNamespaceOwnerMismatch     = errors.New("service namespace is owned by another service account")
	ErrServiceNamespacePermissionRemoval = errors.New("registered service namespace permissions are additive-only")
	ErrServiceNamespaceRoleRemoval       = errors.New("registered service namespace role bindings are additive-only")
	ErrServiceNamespaceDomainChange      = errors.New("registered service namespace domain is immutable")
)

type ServiceNamespaceRegistration struct {
	Namespace           *models.ServiceNamespace
	Created             bool
	Changed             bool
	NeedsReconciliation bool
}

// ServiceNamespaceRepository manages registered service namespace records.
type ServiceNamespaceRepository interface {
	datastore.BaseRepository[*models.ServiceNamespace]
	GetByNamespace(ctx context.Context, namespace string) (*models.ServiceNamespace, error)
	ListAll(ctx context.Context) ([]*models.ServiceNamespace, error)
	RegisterOwned(
		ctx context.Context,
		namespace *models.ServiceNamespace,
		ownerServiceAccountID string,
	) (*ServiceNamespaceRegistration, error)
	MarkReconciled(ctx context.Context, namespace, ownerServiceAccountID string, generation int64) error
}

type serviceNamespaceRepository struct {
	datastore.BaseRepository[*models.ServiceNamespace]
}

func NewServiceNamespaceRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) ServiceNamespaceRepository {
	return &serviceNamespaceRepository{
		BaseRepository: datastore.NewBaseRepository[*models.ServiceNamespace](
			ctx, dbPool, workMan, func() *models.ServiceNamespace { return &models.ServiceNamespace{} },
		),
	}
}

func (r *serviceNamespaceRepository) GetByNamespace(ctx context.Context, namespace string) (*models.ServiceNamespace, error) {
	// Service namespaces are global — skip tenant scoping.
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	ns := &models.ServiceNamespace{}
	err := r.Pool().DB(ctx, false).First(ns, "namespace = ?", namespace).Error
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func (r *serviceNamespaceRepository) ListAll(ctx context.Context) ([]*models.ServiceNamespace, error) {
	// Service namespaces are global — skip tenant scoping.
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	var namespaces []*models.ServiceNamespace
	err := r.Pool().DB(ctx, false).Order("namespace").Find(&namespaces).Error
	if err != nil {
		return nil, err
	}
	return namespaces, nil
}

func (r *serviceNamespaceRepository) RegisterOwned(
	ctx context.Context,
	namespace *models.ServiceNamespace,
	ownerServiceAccountID string,
) (*ServiceNamespaceRegistration, error) {
	if namespace == nil || namespace.Namespace == "" || ownerServiceAccountID == "" {
		return nil, errors.New("register service namespace: namespace and owner are required")
	}

	ctx = security.SkipTenancyChecksOnClaims(ctx)
	result := &ServiceNamespaceRegistration{}
	err := r.Pool().DB(ctx, false).Transaction(func(tx *gorm.DB) error {
		namespace.OwnerServiceAccountID = ownerServiceAccountID
		namespace.Generation = 1
		create := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "namespace"}},
			DoNothing: true,
		}).Create(namespace)
		if create.Error != nil {
			return fmt.Errorf("create service namespace registration: %w", create.Error)
		}

		stored := &models.ServiceNamespace{}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("namespace = ?", namespace.Namespace).
			First(stored).Error; err != nil {
			return fmt.Errorf("load service namespace registration: %w", err)
		}
		if stored.OwnerServiceAccountID != ownerServiceAccountID {
			return fmt.Errorf("%w: %s", ErrServiceNamespaceOwnerMismatch, namespace.Namespace)
		}

		if create.RowsAffected == 1 {
			result = &ServiceNamespaceRegistration{
				Namespace: stored, Created: true, Changed: true, NeedsReconciliation: true,
			}
			return nil
		}
		if stored.Domain != namespace.Domain {
			return fmt.Errorf("%w: %s", ErrServiceNamespaceDomainChange, namespace.Namespace)
		}

		storedPermissions := jsonMapStrings(stored.Permissions, "values")
		requestedPermissions := jsonMapStrings(namespace.Permissions, "values")
		for _, permission := range storedPermissions {
			if !slices.Contains(requestedPermissions, permission) {
				return fmt.Errorf("%w: %s.%s", ErrServiceNamespacePermissionRemoval, namespace.Namespace, permission)
			}
		}
		for role := range stored.RoleBindings {
			if _, exists := namespace.RoleBindings[role]; !exists {
				return fmt.Errorf("%w: %s.%s", ErrServiceNamespaceRoleRemoval, namespace.Namespace, role)
			}
			requestedRolePermissions := jsonMapStrings(namespace.RoleBindings, role)
			for _, permission := range jsonMapStrings(stored.RoleBindings, role) {
				if !slices.Contains(requestedRolePermissions, permission) {
					return fmt.Errorf(
						"%w: %s.%s.%s",
						ErrServiceNamespaceRoleRemoval,
						namespace.Namespace,
						role,
						permission,
					)
				}
			}
		}

		changed := !slices.Equal(storedPermissions, requestedPermissions) ||
			!jsonMapsEqual(stored.RoleBindings, namespace.RoleBindings)
		stored.Permissions = namespace.Permissions
		stored.RoleBindings = namespace.RoleBindings
		stored.RegisteredAt = namespace.RegisteredAt
		if changed {
			stored.Generation++
		}
		if err := tx.Model(stored).
			Select("permissions", "role_bindings", "registered_at", "generation").
			Updates(stored).Error; err != nil {
			return fmt.Errorf("update service namespace registration: %w", err)
		}
		result = &ServiceNamespaceRegistration{
			Namespace:           stored,
			Changed:             changed,
			NeedsReconciliation: stored.ReconciledGeneration < stored.Generation,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *serviceNamespaceRepository) MarkReconciled(
	ctx context.Context,
	namespace string,
	ownerServiceAccountID string,
	generation int64,
) error {
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	result := r.Pool().DB(ctx, false).
		Table("service_namespaces").
		Where(
			"namespace = ? AND owner_service_account_id = ? AND generation = ?",
			namespace,
			ownerServiceAccountID,
			generation,
		).
		Update("reconciled_generation", generation)
	if result.Error != nil {
		return fmt.Errorf("mark service namespace reconciled: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return errors.New("mark service namespace reconciled: registration generation changed")
	}
	return nil
}

func jsonMapsEqual(left, right map[string]any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func jsonMapStrings(values map[string]any, key string) []string {
	raw, ok := values[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []string:
		return slices.Clone(typed)
	case []any:
		result := make([]string, 0, len(typed))
		for _, value := range typed {
			if stringValue, ok := value.(string); ok {
				result = append(result, stringValue)
			}
		}
		return result
	default:
		return nil
	}
}
