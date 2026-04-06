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

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

// permissionManifest matches the payload published by services at startup.
type permissionManifest struct {
	Namespace    string              `json:"namespace"`
	Permissions  []string            `json:"permissions"`
	RoleBindings map[string][]string `json:"role_bindings"`
	RegisteredAt time.Time           `json:"registered_at"`
}

// serviceNamespaceResponse is the JSON response for listing service namespaces.
type serviceNamespaceResponse struct {
	Namespace    string              `json:"namespace"`
	Permissions  []string            `json:"permissions"`
	RoleBindings map[string][]string `json:"role_bindings"`
	RegisteredAt *time.Time          `json:"registered_at,omitempty"`
}

// permissionGrantRequest is the JSON request for granting/revoking permissions.
type permissionGrantRequest struct {
	Namespace  string `json:"namespace"`
	Permission string `json:"permission"`
	ProfileID  string `json:"profile_id"`
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

	permList := data.JSONMap{"values": manifest.Permissions}
	roleBindings := make(data.JSONMap, len(manifest.RoleBindings))
	for role, perms := range manifest.RoleBindings {
		roleBindings[role] = perms
	}

	existing, err := prtSrv.ServiceNamespaceRepo.GetByNamespace(ctx, manifest.Namespace)
	if err != nil {
		// Create new
		ns := &models.ServiceNamespace{
			Namespace:    manifest.Namespace,
			Permissions:  permList,
			RoleBindings: roleBindings,
			RegisteredAt: &manifest.RegisteredAt,
		}
		if createErr := prtSrv.ServiceNamespaceRepo.Create(ctx, ns); createErr != nil {
			logger.WithError(createErr).Error("failed to create service namespace")
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
		// Update existing
		existing.Permissions = permList
		existing.RoleBindings = roleBindings
		existing.RegisteredAt = &manifest.RegisteredAt
		if _, saveErr := prtSrv.ServiceNamespaceRepo.Update(ctx, existing, "permissions", "role_bindings", "registered_at"); saveErr != nil {
			logger.WithError(saveErr).Error("failed to update service namespace")
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}
	}

	logger.WithField("namespace", manifest.Namespace).Debug("permission manifest registered")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(map[string]any{"registered": true})
}

// ListServiceNamespaces handles GET /permissions — returns all registered service namespaces.
func (prtSrv *TenancyServer) ListServiceNamespaces(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	namespaces, err := prtSrv.ServiceNamespaceRepo.ListAll(ctx)
	if err != nil {
		http.Error(rw, "failed to list namespaces", http.StatusInternalServerError)
		return
	}

	result := make([]serviceNamespaceResponse, 0, len(namespaces))
	for _, ns := range namespaces {
		result = append(result, toServiceNamespaceResponse(ns))
	}

	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{"data": result})
}

// GrantPermission handles POST /permissions/grant — creates a granted_* Keto tuple.
func (prtSrv *TenancyServer) GrantPermission(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := util.Log(ctx)

	var grantReq permissionGrantRequest
	if err := json.NewDecoder(req.Body).Decode(&grantReq); err != nil {
		http.Error(rw, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := prtSrv.validatePermissionRequest(ctx, grantReq); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	// Build the granted_* Keto tuple
	claims := security.ClaimsFromContext(ctx)
	tenantID := claims.GetTenantID()
	partitionID := claims.GetPartitionID()
	tenancyPath := fmt.Sprintf("%s/%s", tenantID, partitionID)

	tuple := authz.BuildPermissionTuple(grantReq.Namespace, tenancyPath, grantReq.Permission, grantReq.ProfileID)

	payload := events.TuplesToPayload([]security.RelationTuple{tuple})
	if err := prtSrv.eventsMan.Emit(ctx, events.EventKeyAuthzTupleWrite, payload); err != nil {
		logger.WithError(err).Error("failed to emit permission grant tuple")
		http.Error(rw, "failed to grant permission", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(map[string]any{"granted": true})
}

// RevokePermission handles POST /permissions/revoke — deletes a granted_* Keto tuple.
func (prtSrv *TenancyServer) RevokePermission(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := util.Log(ctx)

	var revokeReq permissionGrantRequest
	if err := json.NewDecoder(req.Body).Decode(&revokeReq); err != nil {
		http.Error(rw, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := prtSrv.validatePermissionRequest(ctx, revokeReq); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	claims := security.ClaimsFromContext(ctx)
	tenantID := claims.GetTenantID()
	partitionID := claims.GetPartitionID()
	tenancyPath := fmt.Sprintf("%s/%s", tenantID, partitionID)

	tuple := authz.BuildPermissionTuple(revokeReq.Namespace, tenancyPath, revokeReq.Permission, revokeReq.ProfileID)

	payload := events.TuplesToPayload([]security.RelationTuple{tuple})
	if err := prtSrv.eventsMan.Emit(ctx, events.EventKeyAuthzTupleDelete, payload); err != nil {
		logger.WithError(err).Error("failed to emit permission revoke tuple")
		http.Error(rw, "failed to revoke permission", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(map[string]any{"revoked": true})
}

// validatePermissionRequest checks that the namespace and permission exist in
// the service namespace registry.
func (prtSrv *TenancyServer) validatePermissionRequest(ctx context.Context, req permissionGrantRequest) error {
	if req.Namespace == "" || req.Permission == "" || req.ProfileID == "" {
		return fmt.Errorf("namespace, permission, and profile_id are required")
	}

	ns, err := prtSrv.ServiceNamespaceRepo.GetByNamespace(ctx, req.Namespace)
	if err != nil {
		return fmt.Errorf("namespace %q not registered", req.Namespace)
	}

	perms := extractPermissions(ns.Permissions)
	if !slices.Contains(perms, req.Permission) {
		return fmt.Errorf("permission %q not available in namespace %q", req.Permission, req.Namespace)
	}

	return nil
}

func toServiceNamespaceResponse(ns *models.ServiceNamespace) serviceNamespaceResponse {
	resp := serviceNamespaceResponse{
		Namespace:    ns.Namespace,
		Permissions:  extractPermissions(ns.Permissions),
		RoleBindings: extractRoleBindings(ns.RoleBindings),
		RegisteredAt: ns.RegisteredAt,
	}
	return resp
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
