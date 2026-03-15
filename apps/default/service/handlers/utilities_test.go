package handlers

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type UtilitiesTestSuite struct {
	suite.Suite
}

func (s *UtilitiesTestSuite) TestIsInternalSystemScoped() {
	s.True(isInternalSystemScoped([]string{"openid", "internal"}))
	s.False(isInternalSystemScoped([]string{"openid", "external"}))
	s.False(isInternalSystemScoped([]string{"openid"}))
	s.False(isInternalSystemScoped(nil))
}

func (s *UtilitiesTestSuite) TestIsExternalSystemScoped() {
	s.True(isExternalSystemScoped([]string{"openid", "external"}))
	s.False(isExternalSystemScoped([]string{"openid", "internal"}))
	s.False(isExternalSystemScoped([]string{"openid"}))
	s.False(isExternalSystemScoped(nil))
}

func (s *UtilitiesTestSuite) TestIsServiceAccountScoped() {
	s.True(isServiceAccountScoped([]string{"internal"}))
	s.True(isServiceAccountScoped([]string{"external"}))
	s.False(isServiceAccountScoped([]string{"openid"}))
	s.False(isServiceAccountScoped(nil))
}

func (s *UtilitiesTestSuite) TestValidateScopeMatchesSAType() {
	s.NoError(validateScopeMatchesSAType([]string{"external"}, "external"))
	s.NoError(validateScopeMatchesSAType([]string{"internal"}, "internal"))
	s.Error(validateScopeMatchesSAType([]string{"external"}, "internal"))
	s.Error(validateScopeMatchesSAType([]string{"internal"}, "external"))
	s.NoError(validateScopeMatchesSAType([]string{"openid"}, "internal"))
}

func (s *UtilitiesTestSuite) TestIsNonUserRole_StringSlice() {
	s.True(isNonUserRole([]string{"internal"}))
	s.True(isNonUserRole([]string{"external"}))
	s.True(isNonUserRole([]string{"user", "internal"}))
	s.False(isNonUserRole([]string{"user"}))
	s.False(isNonUserRole([]string{}))
}

func (s *UtilitiesTestSuite) TestIsNonUserRole_AnySlice() {
	s.True(isNonUserRole([]any{"internal"}))
	s.True(isNonUserRole([]any{"external"}))
	s.True(isNonUserRole([]any{"user", "external"}))
	s.False(isNonUserRole([]any{"user"}))
	s.False(isNonUserRole([]any{}))
	s.False(isNonUserRole([]any{123, true}))
}

func (s *UtilitiesTestSuite) TestIsNonUserRole_OtherTypes() {
	s.False(isNonUserRole(nil))
	s.False(isNonUserRole("internal"))
	s.False(isNonUserRole(123))
}

func (s *UtilitiesTestSuite) TestRoleConstants() {
	s.Equal("internal", RoleSystemInternal)
	s.Equal("external", RoleSystemExternal)
}

func TestUtilities(t *testing.T) {
	suite.Run(t, new(UtilitiesTestSuite))
}
