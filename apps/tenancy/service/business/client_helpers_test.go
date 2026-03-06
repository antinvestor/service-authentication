package business

import (
	"testing"

	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/suite"
)

type ClientHelpersTestSuite struct {
	suite.Suite
}

// --- toJSONMapSlice ---

func (s *ClientHelpersTestSuite) TestToJSONMapSlice_Values() {
	result := toJSONMapSlice("types", []string{"a", "b"})
	s.NotNil(result)
	types, ok := result["types"].([]any)
	s.True(ok)
	s.Len(types, 2)
	s.Equal("a", types[0])
	s.Equal("b", types[1])
}

func (s *ClientHelpersTestSuite) TestToJSONMapSlice_Empty() {
	s.Nil(toJSONMapSlice("types", nil))
	s.Nil(toJSONMapSlice("types", []string{}))
}

// --- GetStringSlice ---

func (s *ClientHelpersTestSuite) TestGetStringSlice_AnySlice() {
	m := data.JSONMap{"roles": []any{"admin", "user"}}
	result := GetStringSlice(m, "roles")
	s.Equal([]string{"admin", "user"}, result)
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_StringSlice() {
	m := data.JSONMap{"roles": []string{"admin"}}
	result := GetStringSlice(m, "roles")
	s.Equal([]string{"admin"}, result)
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_CommaSeparated() {
	m := data.JSONMap{"scopes": "openid,offline"}
	result := GetStringSlice(m, "scopes")
	s.Equal([]string{"openid", "offline"}, result)
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_SingleString() {
	m := data.JSONMap{"scope": "openid"}
	result := GetStringSlice(m, "scope")
	s.Equal([]string{"openid"}, result)
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_EmptyString() {
	m := data.JSONMap{"scope": ""}
	s.Nil(GetStringSlice(m, "scope"))
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_Nil() {
	s.Nil(GetStringSlice(nil, "key"))
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_MissingKey() {
	m := data.JSONMap{"other": "val"}
	s.Nil(GetStringSlice(m, "key"))
}

func (s *ClientHelpersTestSuite) TestGetStringSlice_NonStringEntries() {
	m := data.JSONMap{"mixed": []any{"valid", 123, "also_valid"}}
	result := GetStringSlice(m, "mixed")
	s.Equal([]string{"valid", "also_valid"}, result)
}

func TestClientHelpers(t *testing.T) {
	suite.Run(t, new(ClientHelpersTestSuite))
}
