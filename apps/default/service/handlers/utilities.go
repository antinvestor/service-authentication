package handlers

import (
	"fmt"
	"slices"

	"github.com/pitabwire/frame/security/openid"
)

// Scope-to-Role Mapping Convention:
//
// Service accounts use a two-layer naming convention:
//   - Scopes (Hydra/OAuth2 level): short form from frame constants
//     "system_int"  (openid.ConstSystemScopeInternal) — internal service accounts
//     "system_ext"  (openid.ConstSystemScopeExternal) — external service accounts
//   - Roles (token claims): long form for semantic clarity
//     "system_internal" — internal service accounts
//     "system_external" — external service accounts
//
// The isInternalSystemScoped / isExternalSystemScoped functions check scopes (short form).
// The isNonUserRole function checks roles (long form).

// RoleSystemInternal is the long-form role claim for internal service accounts.
const RoleSystemInternal = "system_internal"

// RoleSystemExternal is the long-form role claim for external service accounts.
const RoleSystemExternal = "system_external"

func isInternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, openid.ConstSystemScopeInternal)
}

func isExternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, openid.ConstSystemScopeExternal)
}

func isServiceAccountScoped(grantedScopes []string) bool {
	return isInternalSystemScoped(grantedScopes) || isExternalSystemScoped(grantedScopes)
}

// validateScopeMatchesSAType checks that the granted scope is consistent with the SA type.
// Returns an error if the scope implies a different SA type than what's registered.
func validateScopeMatchesSAType(grantedScopes []string, saType string) error {
	if isExternalSystemScoped(grantedScopes) && saType != "external" {
		return fmt.Errorf("scope system_ext does not match SA type %q", saType)
	}
	if isInternalSystemScoped(grantedScopes) && saType == "external" {
		return fmt.Errorf("scope system_int does not match SA type %q", saType)
	}
	return nil
}

// isNonUserRole checks whether the roles claim contains a non-interactive role
// (system_internal or system_external). It handles both []string and []any forms
// since JSON-unmarshalled payloads use []any.
func isNonUserRole(roles any) bool {
	nonUserRoles := []string{RoleSystemInternal, RoleSystemExternal}

	switch typed := roles.(type) {
	case []string:
		for _, r := range typed {
			if slices.Contains(nonUserRoles, r) {
				return true
			}
		}
	case []any:
		for _, r := range typed {
			if s, ok := r.(string); ok && slices.Contains(nonUserRoles, s) {
				return true
			}
		}
	}
	return false
}
