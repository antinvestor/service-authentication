package events

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/suite"
)

type SyncServiceAccountHelpersTestSuite struct {
	suite.Suite
}

// --- extractAudienceNamespaces ---

func (s *SyncServiceAccountHelpersTestSuite) TestExtractAudienceNamespaces_AnySlice() {
	m := data.JSONMap{"namespaces": []any{"service_profile", "service_devices"}}
	s.Equal([]string{"service_profile", "service_devices"}, extractAudienceNamespaces(m))
}

func (s *SyncServiceAccountHelpersTestSuite) TestExtractAudienceNamespaces_StringSlice() {
	m := data.JSONMap{"namespaces": []string{"ns1"}}
	s.Equal([]string{"ns1"}, extractAudienceNamespaces(m))
}

func (s *SyncServiceAccountHelpersTestSuite) TestExtractAudienceNamespaces_CommaSep() {
	m := data.JSONMap{"namespaces": "ns1,ns2"}
	s.Equal([]string{"ns1", "ns2"}, extractAudienceNamespaces(m))
}

func (s *SyncServiceAccountHelpersTestSuite) TestExtractAudienceNamespaces_Single() {
	m := data.JSONMap{"namespaces": "ns1"}
	s.Equal([]string{"ns1"}, extractAudienceNamespaces(m))
}

func (s *SyncServiceAccountHelpersTestSuite) TestExtractAudienceNamespaces_Nil() {
	s.Nil(extractAudienceNamespaces(nil))
}

func (s *SyncServiceAccountHelpersTestSuite) TestExtractAudienceNamespaces_MissingKey() {
	s.Nil(extractAudienceNamespaces(data.JSONMap{}))
}

// --- buildServiceAccountHydraPayload ---

func (s *SyncServiceAccountHelpersTestSuite) TestBuildPayload_Internal() {
	sa := &models.ServiceAccount{
		ClientID:  "sa-internal",
		ProfileID: "prof-1",
		Type:      "internal",
		Audiences: data.JSONMap{"namespaces": []any{"service_profile"}},
	}

	payload := buildServiceAccountHydraPayload(sa)
	s.Equal("sa-sa-internal", payload["client_name"])
	s.Equal("sa-internal", payload["client_id"])
	s.Equal("system_int openid", payload["scope"])
	s.Equal("prof-1", payload["subject"])
	s.Equal([]string{"client_credentials"}, payload["grant_types"])
	s.Equal("none", payload["token_endpoint_auth_method"])
}

func (s *SyncServiceAccountHelpersTestSuite) TestBuildPayload_External() {
	sa := &models.ServiceAccount{
		ClientID:  "sa-external",
		ProfileID: "prof-2",
		Type:      "external",
	}

	payload := buildServiceAccountHydraPayload(sa)
	s.Equal("system_ext openid", payload["scope"])
}

func (s *SyncServiceAccountHelpersTestSuite) TestBuildPayload_WithSecret() {
	sa := &models.ServiceAccount{
		ClientID:     "sa-secret",
		ProfileID:    "prof-3",
		ClientSecret: "s3cr3t",
		Type:         "internal",
	}

	payload := buildServiceAccountHydraPayload(sa)
	s.Equal("s3cr3t", payload["client_secret"])
	s.Equal("client_secret_post", payload["token_endpoint_auth_method"])
}

// --- ServiceAccountSyncEvent validation ---

func (s *SyncServiceAccountHelpersTestSuite) TestSASyncEvent_Name() {
	e := &ServiceAccountSyncEvent{}
	s.Equal(EventKeyServiceAccountSynchronization, e.Name())
}

func (s *SyncServiceAccountHelpersTestSuite) TestSASyncEvent_PayloadType() {
	e := &ServiceAccountSyncEvent{}
	s.IsType(&map[string]any{}, e.PayloadType())
}

func (s *SyncServiceAccountHelpersTestSuite) TestSASyncEvent_Validate_Valid() {
	e := &ServiceAccountSyncEvent{}
	m := map[string]any{"id": "sa-1"}
	s.NoError(e.Validate(context.Background(), &m))
}

func (s *SyncServiceAccountHelpersTestSuite) TestSASyncEvent_Validate_MissingID() {
	e := &ServiceAccountSyncEvent{}
	m := map[string]any{}
	s.Error(e.Validate(context.Background(), &m))
}

func (s *SyncServiceAccountHelpersTestSuite) TestSASyncEvent_Validate_WrongType() {
	e := &ServiceAccountSyncEvent{}
	s.Error(e.Validate(context.Background(), "wrong"))
}

func TestSyncServiceAccountHelpers(t *testing.T) {
	suite.Run(t, new(SyncServiceAccountHelpersTestSuite))
}
