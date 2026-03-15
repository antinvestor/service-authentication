package handlers

import (
	"fmt"
	"slices"
)

// Service account types used as both OAuth2 scopes and JWT role claims.
// The SA type ("internal"/"external") is passed through directly — no
// transformation between scope and role naming.
const (
	SATypeInternal = "internal"
	SATypeExternal = "external"
)

// Kept for backward compatibility — code that references these constants
// will continue to compile. New code should use SATypeInternal/SATypeExternal.
const RoleSystemInternal = SATypeInternal
const RoleSystemExternal = SATypeExternal

func isInternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, SATypeInternal)
}

func isExternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, SATypeExternal)
}

func isServiceAccountScoped(grantedScopes []string) bool {
	return isInternalSystemScoped(grantedScopes) || isExternalSystemScoped(grantedScopes)
}

func isNonUserRole(roles any) bool {
	switch typed := roles.(type) {
	case []string:
		return slices.Contains(typed, SATypeInternal) || slices.Contains(typed, SATypeExternal)
	case []any:
		for _, role := range typed {
			roleName, ok := role.(string)
			if !ok {
				continue
			}
			if roleName == SATypeInternal || roleName == SATypeExternal {
				return true
			}
		}
	}
	return false
}

// validateScopeMatchesSAType checks that the granted scope is consistent with the SA type.
func validateScopeMatchesSAType(grantedScopes []string, saType string) error {
	if !isServiceAccountScoped(grantedScopes) {
		return nil
	}
	if isExternalSystemScoped(grantedScopes) && saType != SATypeExternal {
		return fmt.Errorf("scope %q does not match SA type %q", SATypeExternal, saType)
	}
	if isInternalSystemScoped(grantedScopes) && saType == SATypeExternal {
		return fmt.Errorf("scope %q does not match SA type %q", SATypeInternal, saType)
	}
	return nil
}
