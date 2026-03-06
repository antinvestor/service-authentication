package events

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/suite"
)

type SyncClientHelpersTestSuite struct {
	suite.Suite
}

// --- getStringSlice ---

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_AnySlice() {
	m := data.JSONMap{"types": []any{"a", "b"}}
	s.Equal([]string{"a", "b"}, getStringSlice(m, "types"))
}

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_StringSlice() {
	m := data.JSONMap{"types": []string{"x"}}
	s.Equal([]string{"x"}, getStringSlice(m, "types"))
}

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_CommaSeparated() {
	m := data.JSONMap{"types": "a,b,c"}
	s.Equal([]string{"a", "b", "c"}, getStringSlice(m, "types"))
}

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_SingleString() {
	m := data.JSONMap{"types": "single"}
	s.Equal([]string{"single"}, getStringSlice(m, "types"))
}

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_EmptyString() {
	m := data.JSONMap{"types": ""}
	s.Nil(getStringSlice(m, "types"))
}

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_Nil() {
	s.Nil(getStringSlice(nil, "types"))
}

func (s *SyncClientHelpersTestSuite) TestGetStringSlice_MissingKey() {
	s.Nil(getStringSlice(data.JSONMap{}, "types"))
}

// --- buildClientHydraPayload ---

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_Basic() {
	cl := &models.Client{
		Name:     "Test Client",
		ClientID: "test-client-id",
		Type:     "public",
		Scopes:   "openid offline",
	}

	payload := buildClientHydraPayload(cl, "")
	s.Equal("Test Client", payload["client_name"])
	s.Equal("test-client-id", payload["client_id"])
	s.Equal("openid offline", payload["scope"])
	s.Equal("none", payload["token_endpoint_auth_method"])
	s.NotContains(payload, "subject")
}

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_WithProfile() {
	cl := &models.Client{
		Name:     "SA Client",
		ClientID: "sa-id",
		Type:     "internal",
	}

	payload := buildClientHydraPayload(cl, "profile-1")
	s.Equal("profile-1", payload["subject"])
	// No secret → auth method = none
	s.Equal("none", payload["token_endpoint_auth_method"])
}

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_WithSecret() {
	cl := &models.Client{
		Name:         "Confidential Client",
		ClientID:     "conf-id",
		ClientSecret: "secret-val",
		Type:         "confidential",
	}

	payload := buildClientHydraPayload(cl, "")
	s.Equal("secret-val", payload["client_secret"])
	s.Equal("client_secret_post", payload["token_endpoint_auth_method"])
}

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_DefaultGrantTypes() {
	cl := &models.Client{
		Name:     "Defaults",
		ClientID: "defaults",
		Type:     "public",
	}

	payload := buildClientHydraPayload(cl, "")
	grantTypes := payload["grant_types"].([]string)
	s.Contains(grantTypes, "authorization_code")
	s.Contains(grantTypes, "refresh_token")
}

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_CustomGrantTypes() {
	cl := &models.Client{
		Name:       "Custom",
		ClientID:   "custom",
		Type:       "internal",
		GrantTypes: data.JSONMap{"types": []any{"client_credentials"}},
	}

	payload := buildClientHydraPayload(cl, "")
	grantTypes := payload["grant_types"].([]string)
	s.Equal([]string{"client_credentials"}, grantTypes)
}

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_WithProperties() {
	cl := &models.Client{
		Name:     "Props",
		ClientID: "props",
		Type:     "public",
		Properties: data.JSONMap{
			"logo_uri":                  "https://example.com/logo.png",
			"post_logout_redirect_uris": []any{"https://example.com/logout"},
		},
	}

	payload := buildClientHydraPayload(cl, "")
	s.Equal("https://example.com/logo.png", payload["logo_uri"])
	s.NotNil(payload["post_logout_redirect_uris"])
}

func (s *SyncClientHelpersTestSuite) TestBuildClientHydraPayload_DefaultScopes() {
	cl := &models.Client{
		Name:     "No Scopes",
		ClientID: "no-scopes",
		Type:     "public",
	}

	payload := buildClientHydraPayload(cl, "")
	s.Equal("openid offline_access profile", payload["scope"])
}

// --- ClientSyncEvent validation ---

func (s *SyncClientHelpersTestSuite) TestClientSyncEvent_Name() {
	e := &ClientSyncEvent{}
	s.Equal(EventKeyClientSynchronization, e.Name())
}

func (s *SyncClientHelpersTestSuite) TestClientSyncEvent_PayloadType() {
	e := &ClientSyncEvent{}
	s.IsType(&map[string]any{}, e.PayloadType())
}

func (s *SyncClientHelpersTestSuite) TestClientSyncEvent_Validate_Valid() {
	e := &ClientSyncEvent{}
	m := map[string]any{"id": "client-1"}
	s.NoError(e.Validate(context.Background(), &m))
}

func (s *SyncClientHelpersTestSuite) TestClientSyncEvent_Validate_MissingID() {
	e := &ClientSyncEvent{}
	m := map[string]any{}
	s.Error(e.Validate(context.Background(), &m))
}

func (s *SyncClientHelpersTestSuite) TestClientSyncEvent_Validate_WrongType() {
	e := &ClientSyncEvent{}
	s.Error(e.Validate(context.Background(), "wrong"))
}

func TestSyncClientHelpers(t *testing.T) {
	suite.Run(t, new(SyncClientHelpersTestSuite))
}
