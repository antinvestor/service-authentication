package hydra

import (
	"context"
	"fmt"
	"net/http"

	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"
	"github.com/pkg/errors"
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
		"operation":       "AcceptLoginRequest",
		"admin_url":       h.adminURL,
		"login_challenge": params.LoginChallenge,
		"subject_id":      params.SubjectID,
	})

	logger.Debug("accepting Hydra login request")

	// Essential OAuth2 validation
	if params.LoginChallenge == "" {
		err := fmt.Errorf("login challenge is required")
		logger.WithError(err).Error("missing login challenge")
		return "", errors.WithStack(err)
	}
	if params.SubjectID == "" {
		err := fmt.Errorf("subject ID is required")
		logger.WithError(err).Error("missing subject ID")
		return "", errors.WithStack(err)
	}

	// Build login acceptance request
	alr := hydraclientgo.NewAcceptOAuth2LoginRequest(params.SubjectID)
	alr.SetSubject(params.SubjectID)
	alr.SetRemember(params.Remember)
	alr.SetRememberFor(params.RememberDuration)
	alr.SetIdentityProviderSessionId(params.SessionID)
	alr.SetExtendSessionLifespan(params.ExtendSession)
	alr.Amr = []string{} // Authentication methods reference

	apiURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/login/accept", h.adminURL)
	logger.WithField("api_url", apiURL).Debug("calling Hydra admin API")

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
			"api_url": apiURL,
		}).Error("Hydra login acceptance failed")
		return "", errors.WithStack(err)
	}

	if resp == nil {
		err := fmt.Errorf("hydra returned empty response")
		logger.WithError(err).Error("invalid login response")
		return "", errors.WithStack(err)
	}

	logger.WithField("redirect_to", resp.RedirectTo).Debug("login request accepted")
	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error) {
	logger := util.Log(ctx).WithFields(map[string]interface{}{
		"operation":       "GetLoginRequest",
		"admin_url":       h.adminURL,
		"login_challenge": loginChallenge,
	})

	logger.Debug("retrieving Hydra login request")

	if loginChallenge == "" {
		err := fmt.Errorf("login challenge is required")
		logger.WithError(err).Error("missing login challenge")
		return nil, errors.WithStack(err)
	}

	apiURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/login", h.adminURL)
	logger.WithField("api_url", apiURL).Debug("calling Hydra admin API")

	hlr, httpResp, err := h.Cli().GetOAuth2LoginRequest(ctx).LoginChallenge(loginChallenge).Execute()

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
			"api_url": apiURL,
		}).Error("Hydra login request retrieval failed")
		return nil, errors.WithStack(err)
	}

	if hlr == nil {
		err := fmt.Errorf("hydra returned empty login request")
		logger.WithError(err).Error("invalid login response")
		return nil, errors.WithStack(err)
	}

	logger.WithFields(map[string]interface{}{
		"client_id": func() string {
			return hlr.Client.GetClientId()
		}(),
		"skip":    hlr.Skip,
		"subject": hlr.Subject,
	}).Debug("login request retrieved successfully")

	return hlr, nil
}

func (h *DefaultHydra) AcceptConsentRequest(ctx context.Context, params *AcceptConsentRequestParams) (string, error) {
	logger := util.Log(ctx).WithFields(map[string]interface{}{
		"operation":         "AcceptConsentRequest",
		"admin_url":         h.adminURL,
		"consent_challenge": params.ConsentChallenge,
		"grant_scope":       params.GrantScope,
	})

	logger.Debug("accepting Hydra consent request")

	// Essential OAuth2 consent validation
	if params.ConsentChallenge == "" {
		err := fmt.Errorf("consent challenge is required")
		logger.WithError(err).Error("missing consent challenge")
		return "", errors.WithStack(err)
	}
	if len(params.GrantScope) == 0 {
		err := fmt.Errorf("grant scope cannot be empty")
		logger.WithError(err).Error("missing grant scope")
		return "", errors.WithStack(err)
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

	apiURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent/accept", h.adminURL)
	logger.WithField("api_url", apiURL).Debug("calling Hydra admin API")

	resp, httpResp, err := h.Cli().AcceptOAuth2ConsentRequest(ctx).
		ConsentChallenge(params.ConsentChallenge).AcceptOAuth2ConsentRequest(*alr).Execute()

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
			"api_url": apiURL,
		}).Error("Hydra consent acceptance failed")
		return "", errors.WithStack(err)
	}

	if resp == nil {
		err := fmt.Errorf("hydra returned empty response")
		logger.WithError(err).Error("invalid consent response")
		return "", errors.WithStack(err)
	}

	logger.WithField("redirect_to", resp.RedirectTo).Debug("consent request accepted")
	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetConsentRequest(ctx context.Context, consentChallenge string) (*hydraclientgo.OAuth2ConsentRequest, error) {
	logger := util.Log(ctx).WithFields(map[string]interface{}{
		"operation":         "GetConsentRequest",
		"admin_url":         h.adminURL,
		"consent_challenge": consentChallenge,
	})

	logger.Debug("retrieving Hydra consent request")

	if consentChallenge == "" {
		err := fmt.Errorf("consent challenge is required")
		logger.WithError(err).Error("missing consent challenge")
		return nil, errors.WithStack(err)
	}

	apiURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent", h.adminURL)
	logger.WithField("api_url", apiURL).Debug("calling Hydra admin API")

	hcr, httpResp, err := h.Cli().GetOAuth2ConsentRequest(ctx).ConsentChallenge(consentChallenge).Execute()

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
			"api_url": apiURL,
		}).Error("Hydra consent request retrieval failed")
		return nil, errors.WithStack(err)
	}

	if hcr == nil {
		err := fmt.Errorf("hydra returned empty consent request")
		logger.WithError(err).Error("invalid consent response")
		return nil, errors.WithStack(err)
	}

	logger.WithFields(map[string]interface{}{
		"client_id": func() string {
			if hcr.Client != nil {
				return hcr.Client.GetClientId()
			}
			return ""
		}(),
		"subject":            hcr.Subject,
		"requested_scope":    hcr.RequestedScope,
		"requested_audience": hcr.RequestedAccessTokenAudience,
	}).Debug("consent request retrieved successfully")

	return hcr, nil
}

func (h *DefaultHydra) AcceptLogoutRequest(ctx context.Context, params *AcceptLogoutRequestParams) (string, error) {
	logger := util.Log(ctx).WithFields(map[string]interface{}{
		"operation":        "AcceptLogoutRequest",
		"admin_url":        h.adminURL,
		"logout_challenge": params.LogoutChallenge,
	})

	logger.Debug("accepting Hydra logout request")

	if params.LogoutChallenge == "" {
		err := fmt.Errorf("logout challenge is required")
		logger.WithError(err).Error("missing logout challenge")
		return "", errors.WithStack(err)
	}

	apiURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/logout/accept", h.adminURL)
	logger.WithField("api_url", apiURL).Debug("calling Hydra admin API")

	resp, httpResp, err := h.Cli().AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(params.LogoutChallenge).Execute()

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
			"api_url": apiURL,
		}).Error("Hydra logout acceptance failed")
		return "", errors.WithStack(err)
	}

	if resp == nil {
		err := fmt.Errorf("hydra returned empty response")
		logger.WithError(err).Error("invalid logout response")
		return "", errors.WithStack(err)
	}

	logger.WithField("redirect_to", resp.RedirectTo).Debug("logout request accepted")
	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLogoutRequest(ctx context.Context, logoutChallenge string) (*hydraclientgo.OAuth2LogoutRequest, error) {
	logger := util.Log(ctx).WithFields(map[string]interface{}{
		"operation":        "GetLogoutRequest",
		"admin_url":        h.adminURL,
		"logout_challenge": logoutChallenge,
	})

	logger.Debug("retrieving Hydra logout request")

	if logoutChallenge == "" {
		err := fmt.Errorf("logout challenge is required")
		logger.WithError(err).Error("missing logout challenge")
		return nil, errors.WithStack(err)
	}

	apiURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/logout", h.adminURL)
	logger.WithField("api_url", apiURL).Debug("calling Hydra admin API")

	hlr, httpResp, err := h.Cli().GetOAuth2LogoutRequest(ctx).LogoutChallenge(logoutChallenge).Execute()

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"status_code": func() int {
				if httpResp != nil {
					return httpResp.StatusCode
				}
				return 0
			}(),
			"api_url": apiURL,
		}).Error("Hydra logout request retrieval failed")
		return nil, errors.WithStack(err)
	}

	if hlr == nil {
		err := fmt.Errorf("hydra returned empty logout request")
		logger.WithError(err).Error("invalid logout response")
		return nil, errors.WithStack(err)
	}

	logger.WithFields(map[string]interface{}{
		"client_id": func() string {
			if hlr.Client != nil {
				return hlr.Client.GetClientId()
			}
			return ""
		}(),
		"subject": hlr.Subject,
		"sid":     hlr.Sid,
	}).Debug("logout request retrieved successfully")

	return hlr, nil
}
