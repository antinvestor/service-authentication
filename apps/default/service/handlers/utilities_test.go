package handlers

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type UtilitiesTestSuite struct {
	suite.Suite
}

func (s *UtilitiesTestSuite) TestIsInternalSystemScoped() {
	s.True(isInternalSystemScoped([]string{"openid", "system_int"}))
	s.False(isInternalSystemScoped([]string{"openid", "system_ext"}))
	s.False(isInternalSystemScoped([]string{"openid"}))
	s.False(isInternalSystemScoped(nil))
}

func (s *UtilitiesTestSuite) TestIsExternalSystemScoped() {
	s.True(isExternalSystemScoped([]string{"openid", "system_ext"}))
	s.False(isExternalSystemScoped([]string{"openid", "system_int"}))
	s.False(isExternalSystemScoped([]string{"openid"}))
	s.False(isExternalSystemScoped(nil))
}

func (s *UtilitiesTestSuite) TestIsServiceAccountScoped() {
	s.True(isServiceAccountScoped([]string{"system_int"}))
	s.True(isServiceAccountScoped([]string{"system_ext"}))
	s.False(isServiceAccountScoped([]string{"openid"}))
	s.False(isServiceAccountScoped(nil))
}

func (s *UtilitiesTestSuite) TestValidateScopeMatchesSAType() {
	// External scope with external type - OK
	s.NoError(validateScopeMatchesSAType([]string{"system_ext"}, "external"))

	// Internal scope with internal type - OK
	s.NoError(validateScopeMatchesSAType([]string{"system_int"}, "internal"))

	// External scope with internal type - error
	s.Error(validateScopeMatchesSAType([]string{"system_ext"}, "internal"))

	// Internal scope with external type - error
	s.Error(validateScopeMatchesSAType([]string{"system_int"}, "external"))

	// No system scope - OK (no validation needed)
	s.NoError(validateScopeMatchesSAType([]string{"openid"}, "internal"))
}

func (s *UtilitiesTestSuite) TestIsNonUserRole_StringSlice() {
	s.True(isNonUserRole([]string{"system_internal"}))
	s.True(isNonUserRole([]string{"system_external"}))
	s.True(isNonUserRole([]string{"user", "system_internal"}))
	s.False(isNonUserRole([]string{"user"}))
	s.False(isNonUserRole([]string{}))
}

func (s *UtilitiesTestSuite) TestIsNonUserRole_AnySlice() {
	s.True(isNonUserRole([]any{"system_internal"}))
	s.True(isNonUserRole([]any{"system_external"}))
	s.True(isNonUserRole([]any{"user", "system_external"}))
	s.False(isNonUserRole([]any{"user"}))
	s.False(isNonUserRole([]any{}))
	// Non-string values in []any
	s.False(isNonUserRole([]any{123, true}))
}

func (s *UtilitiesTestSuite) TestIsNonUserRole_OtherTypes() {
	s.False(isNonUserRole(nil))
	s.False(isNonUserRole("system_internal"))
	s.False(isNonUserRole(123))
}

func (s *UtilitiesTestSuite) TestRoleConstants() {
	s.Equal("system_internal", RoleSystemInternal)
	s.Equal("system_external", RoleSystemExternal)
}

func TestUtilities(t *testing.T) {
	suite.Run(t, new(UtilitiesTestSuite))
}
