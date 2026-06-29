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

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// permissionManifest matches the payload published by services at startup.
type permissionManifest struct {
	Namespace    string              `json:"namespace"`
	Domain       string              `json:"domain,omitempty"`
	Permissions  []string            `json:"permissions"`
	RoleBindings map[string][]string `json:"role_bindings"`
	RegisteredAt time.Time           `json:"registered_at"`
}

// NewInternalPermissionsHandler returns an HTTP handler for the internal
// (unauthenticated) permission manifest registration endpoint. This is only
// accessible within the cluster — not exposed through the API gateway.
func (prtSrv *TenancyServer) NewInternalPermissionsHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		prtSrv.registerPermissionManifest(rw, req)
	})
}

// registerPermissionManifest handles POST requests to register a service's
// permission manifest. It upserts the service namespace record.
func (prtSrv *TenancyServer) registerPermissionManifest(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	logger := util.Log(ctx)

	var manifest permissionManifest
	if err := json.NewDecoder(req.Body).Decode(&manifest); err != nil {
		http.Error(rw, "invalid request body", http.StatusBadRequest)
		return
	}

	if manifest.Namespace == "" {
		http.Error(rw, "namespace is required", http.StatusBadRequest)
		return
	}

	created, err := prtSrv.upsertServiceNamespace(ctx, manifest)
	if err != nil {
		logger.WithError(err).Error("failed to upsert service namespace")
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	// When a brand-new service joins the platform, backfill root super-user
	// tuples for it synchronously so platform owners can grant permissions in
	// the namespace immediately. Re-registrations skip this step — the set
	// is stable.
	if created {
		if backfillErr := business.EnsureRootAuthorization(ctx, business.RootAuthorizationDeps{
			AccessRepo:           prtSrv.AccessRepo,
			AccessRoleRepo:       prtSrv.AccessRoleRepo,
			PartitionRoleRepo:    prtSrv.PartitionRoleRepo,
			ServiceNamespaceRepo: prtSrv.ServiceNamespaceRepo,
			Authorizer:           prtSrv.svc.SecurityManager().GetAuthorizer(ctx),
		}); backfillErr != nil {
			logger.WithError(backfillErr).Error("root authz backfill for new namespace failed")
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}
	}

	logger.WithField("namespace", manifest.Namespace).Debug("permission manifest registered")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(map[string]any{"registered": true})
}

// upsertServiceNamespace persists a manifest and reports whether the namespace
// record was newly created (true) or updated in place (false). Callers use the
// flag to decide whether to backfill root-user tuples for the new namespace.
func (prtSrv *TenancyServer) upsertServiceNamespace(ctx context.Context, manifest permissionManifest) (bool, error) {
	permList := data.JSONMap{"values": manifest.Permissions}
	roleBindings := make(data.JSONMap, len(manifest.RoleBindings))
	for role, perms := range manifest.RoleBindings {
		roleBindings[role] = perms
	}

	domain := manifest.Domain
	if domain == "" {
		domain = models.DomainDefault
	}

	existing, err := prtSrv.ServiceNamespaceRepo.GetByNamespace(ctx, manifest.Namespace)
	if err != nil {
		ns := &models.ServiceNamespace{
			Namespace:    manifest.Namespace,
			Domain:       domain,
			Permissions:  permList,
			RoleBindings: roleBindings,
			RegisteredAt: &manifest.RegisteredAt,
		}
		if createErr := prtSrv.ServiceNamespaceRepo.Create(ctx, ns); createErr != nil {
			return false, createErr
		}
		return true, nil
	}

	existing.Domain = domain
	existing.Permissions = permList
	existing.RoleBindings = roleBindings
	existing.RegisteredAt = &manifest.RegisteredAt
	_, err = prtSrv.ServiceNamespaceRepo.Update(ctx, existing, "domain", "permissions", "role_bindings", "registered_at")
	return false, err
}

// ListServiceNamespaces implements the Connect RPC to list all registered service namespaces.
func (prtSrv *TenancyServer) ListServiceNamespaces(
	ctx context.Context,
	_ *connect.Request[tenancyv1.ListServiceNamespacesRequest],
) (*connect.Response[tenancyv1.ListServiceNamespacesResponse], error) {
	namespaces, err := prtSrv.ServiceNamespaceRepo.ListAll(ctx)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}

	result := make([]*tenancyv1.ServiceNamespaceObject, 0, len(namespaces))
	for _, ns := range namespaces {
		result = append(result, toServiceNamespaceProto(ns))
	}

	return connect.NewResponse(&tenancyv1.ListServiceNamespacesResponse{Data: result}), nil
}

// GrantPermission implements the Connect RPC to grant a specific permission to a profile.
func (prtSrv *TenancyServer) GrantPermission(
	ctx context.Context,
	req *connect.Request[tenancyv1.GrantPermissionRequest],
) (*connect.Response[tenancyv1.GrantPermissionResponse], error) {
	if err := prtSrv.validatePermission(ctx, req.Msg.GetNamespace(), req.Msg.GetPermission()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	claims := security.ClaimsFromContext(ctx)
	tenancyPath := fmt.Sprintf("%s/%s", claims.GetTenantID(), claims.GetPartitionID())

	tuple := authz.BuildPermissionTuple(req.Msg.GetNamespace(), tenancyPath, req.Msg.GetPermission(), req.Msg.GetProfileId())
	payload := events.TuplesToPayload([]security.RelationTuple{tuple})

	if err := prtSrv.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); err != nil {
		util.Log(ctx).WithError(err).Error("failed to emit permission grant tuple")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to grant permission"))
	}

	return connect.NewResponse(&tenancyv1.GrantPermissionResponse{Succeeded: true}), nil
}

// RevokePermission implements the Connect RPC to revoke a specific permission from a profile.
func (prtSrv *TenancyServer) RevokePermission(
	ctx context.Context,
	req *connect.Request[tenancyv1.RevokePermissionRequest],
) (*connect.Response[tenancyv1.RevokePermissionResponse], error) {
	if err := prtSrv.validatePermission(ctx, req.Msg.GetNamespace(), req.Msg.GetPermission()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	claims := security.ClaimsFromContext(ctx)
	tenancyPath := fmt.Sprintf("%s/%s", claims.GetTenantID(), claims.GetPartitionID())

	tuple := authz.BuildPermissionTuple(req.Msg.GetNamespace(), tenancyPath, req.Msg.GetPermission(), req.Msg.GetProfileId())
	payload := events.TuplesToPayload([]security.RelationTuple{tuple})

	if err := prtSrv.eventsMan.Emit(ctx, events.EventKeyAuthzTupleDelete, payload); err != nil {
		util.Log(ctx).WithError(err).Error("failed to emit permission revoke tuple")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to revoke permission"))
	}

	return connect.NewResponse(&tenancyv1.RevokePermissionResponse{Succeeded: true}), nil
}

// validatePermission checks that the namespace and permission exist in the registry.
func (prtSrv *TenancyServer) validatePermission(ctx context.Context, namespace, permission string) error {
	ns, err := prtSrv.ServiceNamespaceRepo.GetByNamespace(ctx, namespace)
	if err != nil {
		return fmt.Errorf("namespace %q not registered", namespace)
	}

	perms := extractPermissions(ns.Permissions)
	if !slices.Contains(perms, permission) {
		return fmt.Errorf("permission %q not available in namespace %q", permission, namespace)
	}

	return nil
}

func toServiceNamespaceProto(ns *models.ServiceNamespace) *tenancyv1.ServiceNamespaceObject {
	obj := &tenancyv1.ServiceNamespaceObject{
		Namespace:   ns.Namespace,
		Permissions: extractPermissions(ns.Permissions),
	}

	if ns.RegisteredAt != nil {
		obj.RegisteredAt = timestamppb.New(*ns.RegisteredAt)
	}

	roleBindings := extractRoleBindings(ns.RoleBindings)
	if len(roleBindings) > 0 {
		obj.RoleBindings = make(map[string]*tenancyv1.RolePermissionList, len(roleBindings))
		for role, perms := range roleBindings {
			obj.RoleBindings[role] = &tenancyv1.RolePermissionList{Permissions: perms}
		}
	}

	return obj
}

func extractPermissions(m data.JSONMap) []string {
	raw, ok := m["values"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func extractRoleBindings(m data.JSONMap) map[string][]string {
	result := make(map[string][]string, len(m))
	for role, raw := range m {
		switch typed := raw.(type) {
		case []any:
			perms := make([]string, 0, len(typed))
			for _, v := range typed {
				if s, ok := v.(string); ok {
					perms = append(perms, s)
				}
			}
			result[role] = perms
		case []string:
			result[role] = typed
		}
	}
	return result
}
