package events

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/suite"
)

type SyncPartitionHelpersTestSuite struct {
	suite.Suite
}

// --- preparePayload ---

func (s *SyncPartitionHelpersTestSuite) TestPreparePayload_Basic() {
	p := &models.Partition{
		Name:       "Test Partition",
		Properties: data.JSONMap{},
	}

	payload, err := preparePayload("client-1", p)
	s.Require().NoError(err)
	s.Equal("Test Partition", payload["client_name"])
	s.Equal("client-1", payload["client_id"])
	s.Equal("none", payload["token_endpoint_auth_method"])
	// Default scopes applied
	s.Contains(payload["scope"], "openid")
}

func (s *SyncPartitionHelpersTestSuite) TestPreparePayload_WithProperties() {
	p := &models.Partition{
		Name: "Rich Partition",
		Properties: data.JSONMap{
			"logo_uri":                  "https://example.com/logo.png",
			"scope":                     []any{"openid", "offline"},
			"audience":                  []any{"service_profile"},
			"post_logout_redirect_uris": []any{"https://example.com/logout"},
			"redirect_uris":             []any{"https://example.com/callback"},
		},
	}

	payload, err := preparePayload("client-2", p)
	s.Require().NoError(err)
	s.Equal("https://example.com/logo.png", payload["logo_uri"])
	s.Equal("openid offline", payload["scope"])
}

func (s *SyncPartitionHelpersTestSuite) TestPreparePayload_WithSecret() {
	p := &models.Partition{
		Name: "Secret Partition",
		Properties: data.JSONMap{
			"client_secret": "s3cret",
		},
	}

	payload, err := preparePayload("client-3", p)
	s.Require().NoError(err)
	s.Equal("s3cret", payload["client_secret"])
	s.Equal("client_secret_post", payload["token_endpoint_auth_method"])
}

func (s *SyncPartitionHelpersTestSuite) TestPreparePayload_WithSubject() {
	p := &models.Partition{
		Name: "CC Partition",
		Properties: data.JSONMap{
			"subject": "profile-1",
		},
	}

	payload, err := preparePayload("client-4", p)
	s.Require().NoError(err)
	s.Equal("profile-1", payload["subject"])
}

// --- prepareRedirectURIs ---

func (s *SyncPartitionHelpersTestSuite) TestPrepareRedirectURIs_FromSlice() {
	p := &models.Partition{
		Properties: data.JSONMap{
			"redirect_uris": []any{"https://example.com/callback"},
		},
	}
	uris, err := prepareRedirectURIs(p)
	s.Require().NoError(err)
	s.Equal([]string{"https://example.com/callback"}, uris)
}

func (s *SyncPartitionHelpersTestSuite) TestPrepareRedirectURIs_FromString() {
	p := &models.Partition{
		Properties: data.JSONMap{
			"redirect_uris": "https://a.com/cb,https://b.com/cb",
		},
	}
	uris, err := prepareRedirectURIs(p)
	s.Require().NoError(err)
	s.Len(uris, 2)
}

func (s *SyncPartitionHelpersTestSuite) TestPrepareRedirectURIs_Empty() {
	p := &models.Partition{Properties: data.JSONMap{}}
	uris, err := prepareRedirectURIs(p)
	s.Require().NoError(err)
	s.Empty(uris)
}

func (s *SyncPartitionHelpersTestSuite) TestPrepareRedirectURIs_InvalidType() {
	p := &models.Partition{
		Properties: data.JSONMap{
			"redirect_uris": 123,
		},
	}
	_, err := prepareRedirectURIs(p)
	s.Error(err)
}

// --- typeName ---

func (s *SyncPartitionHelpersTestSuite) TestTypeName() {
	s.Equal("string", typeName("hello"))
	s.Equal("int", typeName(42))

	type testStruct struct{}
	s.Equal("*events.testStruct", typeName(&testStruct{}))
}

// --- extractStringList ---

func (s *SyncPartitionHelpersTestSuite) TestExtractStringList_SpaceSeparated() {
	props := map[string]any{"scope": "openid offline profile"}
	s.Equal([]string{"openid", "offline", "profile"}, extractStringList(props, "scope"))
}

func (s *SyncPartitionHelpersTestSuite) TestExtractStringList_CommaSeparated() {
	props := map[string]any{"scope": "openid,offline"}
	s.Equal([]string{"openid", "offline"}, extractStringList(props, "scope"))
}

func (s *SyncPartitionHelpersTestSuite) TestExtractStringList_AnySlice() {
	props := map[string]any{"uris": []any{"https://a.com", "https://b.com"}}
	s.Equal([]string{"https://a.com", "https://b.com"}, extractStringList(props, "uris"))
}

func (s *SyncPartitionHelpersTestSuite) TestExtractStringList_MissingKey() {
	s.Nil(extractStringList(map[string]any{}, "scope"))
}

func (s *SyncPartitionHelpersTestSuite) TestExtractStringList_NilMap() {
	s.Nil(extractStringList(nil, "scope"))
}

func TestSyncPartitionHelpers(t *testing.T) {
	suite.Run(t, new(SyncPartitionHelpersTestSuite))
}
