package handlers

import (
	"slices"

	"github.com/pitabwire/frame/security/openid"
)

func isInternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, openid.ConstSystemScopeInternal)
}

// isNonUserRole checks whether the roles claim contains a non-interactive role
// (system_internal or system_external). It handles both []string and []any forms
// since JSON-unmarshalled payloads use []any.
func isNonUserRole(roles any) bool {
	nonUserRoles := []string{"system_internal", "system_external"}

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
