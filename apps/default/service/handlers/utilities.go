package handlers

import (
	"slices"

	"github.com/pitabwire/frame/security/openid"
)

func isInternalSystemScoped(grantedScopes []string) bool {
	return slices.Contains(grantedScopes, openid.ConstSystemScopeInternal)
}
