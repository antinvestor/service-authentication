package handlers

import (
	"fmt"
	"slices"
)

// Scope-to-Role Mapping Convention:
//
// Service accounts use a two-layer naming convention:
//   - Scopes (Hydra/OAuth2 level): short form from frame constants
//     "system_int"  ("system_int") — internal service accounts
//     "system_ext"  ("system_ext") — external service accounts
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
	return slices.Contains(grantedScopes, "system_int")
}

func isExternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, "system_ext")
}

func isServiceAccountScoped(grantedScopes []string) bool {
	return isInternalSystemScoped(grantedScopes) || isExternalSystemScoped(grantedScopes)
}

func isNonUserRole(roles any) bool {
	switch typed := roles.(type) {
	case []string:
		return slices.Contains(typed, RoleSystemInternal) || slices.Contains(typed, RoleSystemExternal)
	case []any:
		for _, role := range typed {
			roleName, ok := role.(string)
			if !ok {
				continue
			}
			if roleName == RoleSystemInternal || roleName == RoleSystemExternal {
				return true
			}
		}
	}

	return false
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
