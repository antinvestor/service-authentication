package hydra

import (
	"fmt"
	"github.com/pkg/errors"
	"time"
)

import (
	"context"
	hydraclientgo "github.com/ory/hydra-client-go/v2"
	"net/http"
)

type (
	Provider interface {
		Hydra() Hydra
	}
	AcceptLoginRequestParams struct {
		LoginChallenge string
		IdentityID     string
		SessionID      string

		Remember         *bool
		RememberDuration *int64
	}
	AcceptConsentRequestParams struct {
		ConsentChallenge string
		GrantScope       []string
		GrantAudience    []string
		AdditionalParams map[string]interface{}
	}

	AcceptLogoutRequestParams struct {
		LogoutChallenge string
	}

	Hydra interface {
		AcceptLoginRequest(ctx context.Context, params AcceptLoginRequestParams) (string, error)
		GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error)
		AcceptConsentRequest(ctx context.Context, params AcceptConsentRequestParams) (string, error)
		GetConsentRequest(ctx context.Context, consentChallenge string) (*hydraclientgo.OAuth2ConsentRequest, error)
		AcceptLogoutRequest(ctx context.Context, params AcceptLogoutRequestParams) (string, error)
		GetLogoutRequest(ctx context.Context, logoutChallenge string) (*hydraclientgo.OAuth2LogoutRequest, error)
	}
	DefaultHydra struct {
		adminUrl string
	}
)

func NewDefaultHydra(adminUrl string) *DefaultHydra {
	return &DefaultHydra{
		adminUrl: adminUrl,
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
		return "", errors.WithStack(fmt.Errorf("%s parameter is present but empty", query))
	}

	return consentChallenge, nil
}

func (h *DefaultHydra) getAdminURL(_ context.Context) (string, error) {
	return h.adminUrl, nil
}

func (h *DefaultHydra) getAdminAPIClient(ctx context.Context) (hydraclientgo.OAuth2Api, error) {
	url, err := h.getAdminURL(ctx)
	if err != nil {
		return nil, err
	}

	configuration := hydraclientgo.NewConfiguration()
	configuration.Servers = hydraclientgo.ServerConfigurations{{URL: url}}

	configuration.HTTPClient = &http.Client{}
	return hydraclientgo.NewAPIClient(configuration).OAuth2Api, nil
}

func (h *DefaultHydra) AcceptLoginRequest(ctx context.Context, params AcceptLoginRequestParams) (string, error) {

	extendSession := true

	alr := hydraclientgo.NewAcceptOAuth2LoginRequest(params.IdentityID)
	alr.IdentityProviderSessionId = &params.SessionID
	alr.Remember = params.Remember
	alr.RememberFor = params.RememberDuration
	alr.ExtendSessionLifespan = &extendSession
	alr.Amr = []string{}

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return "", err
	}

	resp, _, err := aa.AcceptOAuth2LoginRequest(ctx).LoginChallenge(params.LoginChallenge).AcceptOAuth2LoginRequest(*alr).Execute()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error) {
	if loginChallenge == "" {
		return nil, fmt.Errorf("invalid login_challenge")
	}

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	hlr, _, err := aa.GetOAuth2LoginRequest(ctx).LoginChallenge(loginChallenge).Execute()
	if err != nil {
		return nil, err
	}

	return hlr, nil
}

func (h *DefaultHydra) AcceptConsentRequest(ctx context.Context, params AcceptConsentRequestParams) (string, error) {

	// By default we enable session rememberance for a week
	remember := true
	rememberFor := int64(7 * 24 * time.Hour / time.Second)

	alr := hydraclientgo.NewAcceptOAuth2ConsentRequest()
	alr.GrantScope = params.GrantScope
	alr.GrantAccessTokenAudience = params.GrantAudience
	alr.Remember = &remember
	alr.RememberFor = &rememberFor
	alr.AdditionalProperties = params.AdditionalParams

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return "", err
	}

	resp, _, err := aa.AcceptOAuth2ConsentRequest(ctx).
		ConsentChallenge(params.ConsentChallenge).AcceptOAuth2ConsentRequest(*alr).Execute()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetConsentRequest(ctx context.Context, consentChallenge string) (*hydraclientgo.OAuth2ConsentRequest, error) {
	if consentChallenge == "" {
		return nil, fmt.Errorf("invalid consent_challenge")
	}

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	hlr, _, err := aa.GetOAuth2ConsentRequest(ctx).ConsentChallenge(consentChallenge).Execute()
	if err != nil {
		return nil, err
	}

	return hlr, nil
}

func (h *DefaultHydra) AcceptLogoutRequest(ctx context.Context, params AcceptLogoutRequestParams) (string, error) {

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return "", err
	}

	resp, _, err := aa.AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(params.LogoutChallenge).Execute()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLogoutRequest(ctx context.Context, logoutChallenge string) (*hydraclientgo.OAuth2LogoutRequest, error) {
	if logoutChallenge == "" {
		return nil, fmt.Errorf("invalid logout_challenge")
	}

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	hlr, _, err := aa.GetOAuth2LogoutRequest(ctx).LogoutChallenge(logoutChallenge).Execute()
	if err != nil {
		return nil, err
	}

	return hlr, nil
}
