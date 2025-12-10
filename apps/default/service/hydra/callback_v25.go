package hydra

import (
	"context"
	"fmt"
	"net/http"

	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"
)

type (
	Provider interface {
		Hydra() Hydra
	}
	AcceptLoginRequestParams struct {
		LoginChallenge string
		SubjectID      string
		SessionID      string

		ExtendSession    bool
		Remember         bool
		RememberDuration int64
	}
	AcceptConsentRequestParams struct {
		ConsentChallenge string
		GrantScope       []string
		GrantAudience    []string

		Remember         bool
		RememberDuration int64

		AccessTokenExtras map[string]any
		IdTokenExtras     map[string]any
	}

	AcceptLogoutRequestParams struct {
		LogoutChallenge string
	}

	Hydra interface {
		AcceptLoginRequest(ctx context.Context, params *AcceptLoginRequestParams) (string, error)
		GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error)
		AcceptConsentRequest(ctx context.Context, params *AcceptConsentRequestParams) (string, error)
		GetConsentRequest(ctx context.Context, consentChallenge string) (*hydraclientgo.OAuth2ConsentRequest, error)
		AcceptLogoutRequest(ctx context.Context, params *AcceptLogoutRequestParams) (string, error)
		GetLogoutRequest(ctx context.Context, logoutChallenge string) (*hydraclientgo.OAuth2LogoutRequest, error)
	}
	DefaultHydra struct {
		cli      *hydraclientgo.APIClient
		adminURL string
	}
)

func NewDefaultHydra(httpClient *http.Client, adminUrl string) *DefaultHydra {
	configuration := hydraclientgo.NewConfiguration()
	configuration.Servers = []hydraclientgo.ServerConfiguration{
		{
			URL: adminUrl,
		},
	}
	configuration.HTTPClient = httpClient
	apiClient := hydraclientgo.NewAPIClient(configuration)

	return &DefaultHydra{
		cli:      apiClient,
		adminURL: adminUrl,
	}
}

func GetLoginChallengeID(r *http.Request) (string, error) {
	return getChallengeID(r, "login_challenge")
}

func GetLogoutChallengeID(r *http.Request) (string, error) {
	return getChallengeID(r, "logout_challenge")
}

func GetConsentChallengeID(r *http.Request) (string, error) {
	return getChallengeID(r, "consent_challenge")
}
func getChallengeID(r *http.Request, query string) (string, error) {
	if !r.URL.Query().Has(query) {
		return "", nil
	}

	consentChallenge := r.URL.Query().Get(query)
	if consentChallenge == "" {
		return "", fmt.Errorf("%s parameter is present but empty", query)
	}

	return consentChallenge, nil
}

func (h *DefaultHydra) Cli() hydraclientgo.OAuth2API {
	return h.cli.OAuth2API
}

func (h *DefaultHydra) AcceptLoginRequest(ctx context.Context, params *AcceptLoginRequestParams) (string, error) {
	logger := util.Log(ctx).WithFields(map[string]interface{}{
		"admin_url":       h.adminURL,
		"login_challenge": params.LoginChallenge,
		"subject_id":      params.SubjectID,
	})

	// Essential OAuth2 validation
	if params.LoginChallenge == "" {
		err := fmt.Errorf("login challenge is required")
		logger.WithError(err).Error("missing login challenge")
		return "", err
	}
	if params.SubjectID == "" {
		err := fmt.Errorf("subject ID is required")
		logger.WithError(err).Error("missing subject ID")
		return "", err
	}

	// First validate the login challenge exists before accepting it
	// This mirrors what the test client does implicitly
	loginReq, httpResp, err := h.Cli().GetOAuth2LoginRequest(ctx).
		LoginChallenge(params.LoginChallenge).Execute()
	
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
		}).Error("Hydra login request validation failed")
		return "", err
	}

	if loginReq == nil {
		err = fmt.Errorf("hydra returned empty login request")
		logger.WithError(err).Error("invalid login request validation")
		return "", err
	}

	logger.WithFields(map[string]interface{}{
		"client_id": loginReq.Client.GetClientId(),
		"skip":      loginReq.Skip,
		"subject":   loginReq.Subject,
	}).Debug("login request validated successfully")

	// Build login acceptance request
	alr := hydraclientgo.NewAcceptOAuth2LoginRequest(params.SubjectID)
	alr.SetSubject(params.SubjectID)
	alr.SetRemember(params.Remember)
	alr.SetRememberFor(params.RememberDuration)
	alr.SetIdentityProviderSessionId(params.SessionID)
	alr.SetExtendSessionLifespan(params.ExtendSession)
	alr.Amr = []string{} // Authentication methods reference

	resp, httpResp, err := h.Cli().AcceptOAuth2LoginRequest(ctx).
		LoginChallenge(params.LoginChallenge).AcceptOAuth2LoginRequest(*alr).Execute()

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
		}).Error("Hydra login acceptance failed")
		return "", err
	}

	if resp == nil {
		err = fmt.Errorf("hydra returned empty response")
		logger.WithError(err).Error("invalid login response")
		return "", err
	}

	logger.WithField("redirect_to", resp.RedirectTo).Debug("login request accepted")
	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error) {
	if loginChallenge == "" {
		err := fmt.Errorf("login challenge is required")
		return nil, err
	}

	hlr, _, err := h.Cli().GetOAuth2LoginRequest(ctx).LoginChallenge(loginChallenge).Execute()

	if err != nil {
		return nil, err
	}

	if hlr == nil {
		err := fmt.Errorf("hydra returned empty login request")
		return nil, err
	}

	return hlr, nil
}

func (h *DefaultHydra) AcceptConsentRequest(ctx context.Context, params *AcceptConsentRequestParams) (string, error) {
	// Essential OAuth2 consent validation
	if params.ConsentChallenge == "" {
		err := fmt.Errorf("consent challenge is required")
		return "", err
	}
	if len(params.GrantScope) == 0 {
		err := fmt.Errorf("grant scope cannot be empty")
		return "", err
	}

	// Build consent session data with token extras
	sessionData := hydraclientgo.AcceptOAuth2ConsentRequestSession{
		AccessToken: params.AccessTokenExtras,
		IdToken:     params.IdTokenExtras,
	}

	// Build consent acceptance request
	alr := hydraclientgo.NewAcceptOAuth2ConsentRequest()
	alr.SetGrantScope(params.GrantScope)
	alr.SetGrantAccessTokenAudience(params.GrantAudience)
	alr.SetRemember(params.Remember)
	alr.SetRememberFor(params.RememberDuration)
	alr.SetSession(sessionData)

	resp, _, err := h.Cli().AcceptOAuth2ConsentRequest(ctx).
		ConsentChallenge(params.ConsentChallenge).AcceptOAuth2ConsentRequest(*alr).Execute()

	if err != nil {
		return "", err
	}

	if resp == nil {
		err := fmt.Errorf("hydra returned empty response")
		return "", err
	}

	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetConsentRequest(ctx context.Context, consentChallenge string) (*hydraclientgo.OAuth2ConsentRequest, error) {
	if consentChallenge == "" {
		err := fmt.Errorf("consent challenge is required")
		return nil, err
	}

	hcr, _, err := h.Cli().GetOAuth2ConsentRequest(ctx).ConsentChallenge(consentChallenge).Execute()

	if err != nil {
		return nil, err
	}

	if hcr == nil {
		err := fmt.Errorf("hydra returned empty consent request")
		return nil, err
	}

	return hcr, nil
}

func (h *DefaultHydra) AcceptLogoutRequest(ctx context.Context, params *AcceptLogoutRequestParams) (string, error) {
	if params.LogoutChallenge == "" {
		err := fmt.Errorf("logout challenge is required")
		return "", err
	}

	resp, _, err := h.Cli().AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(params.LogoutChallenge).Execute()

	if err != nil {
		return "", err
	}

	if resp == nil {
		err = fmt.Errorf("hydra returned empty response")
		return "", err
	}

	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLogoutRequest(ctx context.Context, logoutChallenge string) (*hydraclientgo.OAuth2LogoutRequest, error) {
	if logoutChallenge == "" {
		err := fmt.Errorf("logout challenge is required")
		return nil, err
	}

	hlr, _, err := h.Cli().GetOAuth2LogoutRequest(ctx).LogoutChallenge(logoutChallenge).Execute()

	if err != nil {
		return nil, err
	}

	if hlr == nil {
		err = fmt.Errorf("hydra returned empty logout request")
		return nil, err
	}

	return hlr, nil
}
