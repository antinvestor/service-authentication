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
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxPermissionManifestBytes = 256 * 1024

// permissionManifest matches the payload published by services at startup.
type permissionManifest struct {
	Namespace    string              `json:"namespace"`
	Domain       string              `json:"domain,omitempty"`
	Permissions  []string            `json:"permissions"`
	RoleBindings map[string][]string `json:"role_bindings"`
	RegisteredAt time.Time           `json:"registered_at"`
}

// NewPermissionRegistrationHandler accepts authenticated manifests published
// by Frame services during startup.
func (prtSrv *TenancyServer) NewPermissionRegistrationHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		prtSrv.registerPermissionManifest(rw, req)
	})
}

// registerPermissionManifest registers an authenticated service-owned
// permission manifest and triggers generation reconciliation.
//
// Security: requires a valid internal service-account token (AuthenticationMiddleware
// already verified JWT). The caller must present service_account_id in claims and
// that SA must own the namespace (internal, root partition, name/client matches).
func (prtSrv *TenancyServer) registerPermissionManifest(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := util.Log(ctx)

	claims := security.ClaimsFromContext(ctx)
	if claims == nil || !claims.IsInternalSystem() {
		http.Error(rw, "internal service-account token is required", http.StatusForbidden)
		return
	}
	ownerServiceAccountID := serviceAccountIDFromClaims(claims)
	if ownerServiceAccountID == "" {
		http.Error(rw, "service-account identity is required", http.StatusForbidden)
		return
	}

	var manifest permissionManifest
	req.Body = http.MaxBytesReader(rw, req.Body, maxPermissionManifestBytes)
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		http.Error(rw, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(rw, "request body must contain one manifest", http.StatusBadRequest)
		return
	}

	registration, err := business.RegisterPermissionManifest(ctx, business.PermissionRegistryDeps{
		ServiceNamespaceRepo: prtSrv.ServiceNamespaceRepo,
		ServiceAccountRepo:   prtSrv.ServiceAccountRepo,
		PolicyRepo:           prtSrv.AuthorizationPolicyRepo,
		PartitionRepo:        prtSrv.PartitionRepo,
		AccessRepo:           prtSrv.AccessRepo,
		AccessRoleRepo:       prtSrv.AccessRoleRepo,
		PartitionRoleRepo:    prtSrv.PartitionRoleRepo,
		EventsManager:        prtSrv.eventsMan,
		Authorizer:           prtSrv.svc.SecurityManager().GetAuthorizer(ctx),
	}, ownerServiceAccountID, business.PermissionManifest{
		Namespace:    manifest.Namespace,
		Domain:       manifest.Domain,
		Permissions:  manifest.Permissions,
		RoleBindings: manifest.RoleBindings,
	})
	if err != nil {
		switch {
		case errors.Is(err, business.ErrInvalidPermissionManifest):
			http.Error(rw, err.Error(), http.StatusBadRequest)
		case errors.Is(err, business.ErrPermissionManifestOwner):
			http.Error(rw, "service account cannot register this namespace", http.StatusForbidden)
		case errors.Is(err, repository.ErrServiceNamespaceOwnerMismatch),
			errors.Is(err, repository.ErrServiceNamespacePermissionRemoval),
			errors.Is(err, repository.ErrServiceNamespaceRoleRemoval),
			errors.Is(err, repository.ErrServiceNamespaceDomainChange):
			http.Error(rw, err.Error(), http.StatusConflict)
		default:
			logger.WithError(err).Error("failed to register service namespace")
			http.Error(rw, "internal error", http.StatusInternalServerError)
		}
		return
	}

	logger.WithFields(map[string]any{
		"namespace":          manifest.Namespace,
		"service_account_id": ownerServiceAccountID,
		"created":            registration.Created,
		"changed":            registration.Changed,
	}).Info("permission manifest registered")
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(rw).Encode(map[string]any{
		"registered": true,
		"created":    registration.Created,
		"changed":    registration.Changed,
	}); err != nil {
		logger.WithError(err).Warn("failed to encode permission registration response")
	}
}

// serviceAccountIDFromClaims extracts the registering SA id from JWT claims.
//
// Preferred shape (after token-hook fix): claims.Ext["service_account_id"] or a
// top-level claim when mirrored. Legacy tokens nested the id under Ext["ext"]
// because buildServiceAccountClaims used to embed a nested "ext" map inside
// Hydra access-token extras (which Hydra already nests under "ext").
func serviceAccountIDFromClaims(claims *security.AuthenticationClaims) string {
	if claims == nil {
		return ""
	}
	if id := stringClaim(claims.Ext, "service_account_id"); id != "" {
		return id
	}
	// Legacy double-nested shape: ext.ext.service_account_id
	if nested, ok := claims.Ext["ext"].(map[string]any); ok {
		if id := stringClaim(nested, "service_account_id"); id != "" {
			return id
		}
	}
	return ""
}

func stringClaim(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
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
