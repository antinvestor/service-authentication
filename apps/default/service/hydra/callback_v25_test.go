package hydra

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

type HydraTestSuite struct {
	suite.Suite
}

// --- Challenge ID extraction ---

func (s *HydraTestSuite) TestGetLoginChallengeID_Present() {
	req := httptest.NewRequest(http.MethodGet, "/login?login_challenge=abc123", nil)
	id, err := GetLoginChallengeID(req)
	s.NoError(err)
	s.Equal("abc123", id)
}

func (s *HydraTestSuite) TestGetLoginChallengeID_Missing() {
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	id, err := GetLoginChallengeID(req)
	s.NoError(err)
	s.Equal("", id)
}

func (s *HydraTestSuite) TestGetLoginChallengeID_Empty() {
	req := httptest.NewRequest(http.MethodGet, "/login?login_challenge=", nil)
	_, err := GetLoginChallengeID(req)
	s.Error(err)
}

func (s *HydraTestSuite) TestGetConsentChallengeID_Present() {
	req := httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=def456", nil)
	id, err := GetConsentChallengeID(req)
	s.NoError(err)
	s.Equal("def456", id)
}

func (s *HydraTestSuite) TestGetConsentChallengeID_Missing() {
	req := httptest.NewRequest(http.MethodGet, "/consent", nil)
	id, err := GetConsentChallengeID(req)
	s.NoError(err)
	s.Equal("", id)
}

func (s *HydraTestSuite) TestGetLogoutChallengeID_Present() {
	req := httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=ghi789", nil)
	id, err := GetLogoutChallengeID(req)
	s.NoError(err)
	s.Equal("ghi789", id)
}

func (s *HydraTestSuite) TestGetLogoutChallengeID_Empty() {
	req := httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=", nil)
	_, err := GetLogoutChallengeID(req)
	s.Error(err)
}

// --- DefaultHydra validation tests ---

func (s *HydraTestSuite) TestNewDefaultHydra() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	s.NotNil(h)
}

func (s *HydraTestSuite) TestAcceptLoginRequest_EmptyChallenge() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.AcceptLoginRequest(context.Background(), &AcceptLoginRequestParams{
		SubjectID: "sub",
	}, nil, "")
	s.Error(err)
	s.Contains(err.Error(), "login challenge is required")
}

func (s *HydraTestSuite) TestAcceptLoginRequest_EmptySubject() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.AcceptLoginRequest(context.Background(), &AcceptLoginRequestParams{
		LoginChallenge: "challenge-1",
	}, nil, "")
	s.Error(err)
	s.Contains(err.Error(), "subject")
}

func (s *HydraTestSuite) TestGetLoginRequest_EmptyChallenge() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.GetLoginRequest(context.Background(), "")
	s.Error(err)
	s.Contains(err.Error(), "login challenge is required")
}

func (s *HydraTestSuite) TestAcceptConsentRequest_EmptyChallenge() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.AcceptConsentRequest(context.Background(), &AcceptConsentRequestParams{
		GrantScope: []string{"openid"},
	})
	s.Error(err)
	s.Contains(err.Error(), "consent challenge is required")
}

func (s *HydraTestSuite) TestAcceptConsentRequest_EmptyScope() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.AcceptConsentRequest(context.Background(), &AcceptConsentRequestParams{
		ConsentChallenge: "challenge-1",
	})
	s.Error(err)
	s.Contains(err.Error(), "grant scope cannot be empty")
}

func (s *HydraTestSuite) TestGetConsentRequest_EmptyChallenge() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.GetConsentRequest(context.Background(), "")
	s.Error(err)
	s.Contains(err.Error(), "consent challenge is required")
}

func (s *HydraTestSuite) TestAcceptLogoutRequest_EmptyChallenge() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.AcceptLogoutRequest(context.Background(), &AcceptLogoutRequestParams{})
	s.Error(err)
	s.Contains(err.Error(), "logout challenge is required")
}

func (s *HydraTestSuite) TestGetLogoutRequest_EmptyChallenge() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.GetLogoutRequest(context.Background(), "")
	s.Error(err)
	s.Contains(err.Error(), "logout challenge is required")
}

func (s *HydraTestSuite) TestGetOAuth2Client_EmptyClientID() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.GetOAuth2Client(context.Background(), "")
	s.Error(err)
	s.Contains(err.Error(), "client_id is required")
}

func (s *HydraTestSuite) TestGetJsonWebKeySet_EmptySet() {
	h := NewDefaultHydra(http.DefaultClient, "http://localhost:4445")
	_, err := h.GetJsonWebKeySet(context.Background(), "")
	s.Error(err)
	s.Contains(err.Error(), "JWK set name is required")
}

func TestHydra(t *testing.T) {
	suite.Run(t, new(HydraTestSuite))
}
