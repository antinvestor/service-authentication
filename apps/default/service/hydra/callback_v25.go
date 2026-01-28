package hydra

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	hydraclientgo "github.com/ory/hydra-client-go/v25"
)

type (
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
		AcceptLoginRequest(ctx context.Context, params *AcceptLoginRequestParams, loginCtx map[string]any, acr string, amr ...string) (string, error)
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

func NewDefaultHydra(httpClient *http.Client, adminUrl string) Hydra {
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

func (h *DefaultHydra) AcceptLoginRequest(ctx context.Context, params *AcceptLoginRequestParams, loginCtx map[string]any, acr string, amr ...string) (string, error) {

	// Build login acceptance request
	alr := hydraclientgo.NewAcceptOAuth2LoginRequest(params.SubjectID)
	alr.SetSubject(params.SubjectID)
	alr.SetRemember(params.Remember)
	alr.SetRememberFor(params.RememberDuration)
	alr.SetIdentityProviderSessionId(params.SessionID)
	alr.SetExtendSessionLifespan(params.ExtendSession)
	alr.SetAcr(acr) // Authentication methods reference
	alr.SetAmr(amr) // Authentication methods reference
	alr.SetContext(loginCtx)

	resp, _, err := h.Cli().AcceptOAuth2LoginRequest(ctx).
		LoginChallenge(params.LoginChallenge).AcceptOAuth2LoginRequest(*alr).Execute()

	if err != nil {
		var apiErr *hydraclientgo.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("accept login request failed (challenge=%s): %w, response: %s",
				params.LoginChallenge, err, string(apiErr.Body()))
		}
		return "", fmt.Errorf("accept login request failed (challenge=%s): %w", params.LoginChallenge, err)
	}

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
		err = fmt.Errorf("hydra returned empty login request")
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
		err = fmt.Errorf("hydra returned empty response")
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
		err = fmt.Errorf("hydra returned empty consent request")
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
