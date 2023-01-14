package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pitabwire/frame"
	"github.com/stretchr/objx"
	"io"
	"net/http"
	"net/url"
)

func processResp(response *http.Response) (objx.Map, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK &&
		response.StatusCode != http.StatusAccepted &&
		response.StatusCode != http.StatusCreated {
		resp, err := objx.FromJSON(string(body))
		if err != nil {
			return nil, err
		}

		return resp, errors.New(response.Status)
	}

	return objx.FromJSON(string(body))

}

// A little helper that takes type (can be "login" or "consent")
// and a challenge and returns the response from ORY Hydra.
func get(ctx context.Context, flow string, challenge string) (objx.Map, error) {

	service := frame.FromContext(ctx)
	cfg, ok := service.Config().(frame.ConfigurationOAUTH2)
	if !ok {
		return nil, fmt.Errorf("Could not cast configuration to ConfigurationOAUTH2 ")
	}
	params := url.Values{}
	params.Add(fmt.Sprintf("%s_challenge", flow), challenge)

	hydraAdminURL := cfg.GetOauth2ServiceAdminURI()
	formatedUrl := fmt.Sprintf("%s/oauth2/auth/requests/%s", hydraAdminURL, flow)
	baseURL, err := url.Parse(formatedUrl)
	if err != nil {
		return nil, err
	}
	baseURL.RawQuery = params.Encode()

	response, err := http.Get(baseURL.String())
	if err != nil {
		return nil, err
	}

	return processResp(response)
}

// A little helper that takes type (can be "login" or "consent"),
// the action (can be "accept" or "reject") and a challenge
// and returns the response from ORY Hydra.
func put(ctx context.Context, flow string, action string, challenge string, data map[string]interface{}) (objx.Map, error) {

	service := frame.FromContext(ctx)
	cfg, ok := service.Config().(frame.ConfigurationOAUTH2)
	if !ok {
		return nil, fmt.Errorf("Could not cast configuration to ConfigurationOAUTH2 ")
	}

	params := url.Values{}
	params.Add(fmt.Sprintf("%s_challenge", flow), challenge)

	hydraAdminURL := cfg.GetOauth2ServiceAdminURI()
	formattedURL := fmt.Sprintf("%s/oauth2/auth/requests/%s/%s", hydraAdminURL, flow, action)
	baseURL, err := url.Parse(formattedURL)
	if err != nil {
		return nil, err
	}
	baseURL.RawQuery = params.Encode()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	request, err := http.NewRequest(http.MethodPut, baseURL.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	return processResp(response)

}

func GetLoginRequest(ctx context.Context, loginchallenge string) (objx.Map, error) {

	return get(ctx, "login", loginchallenge)
}

func AcceptLoginRequest(ctx context.Context, loginchallenge string, data map[string]interface{}) (objx.Map, error) {

	return put(ctx, "login", "accept", loginchallenge, data)

}

func RejectLoginRequest(ctx context.Context, loginchallenge string, data map[string]interface{}) (objx.Map, error) {

	return put(ctx, "login", "reject", loginchallenge, data)

}

func GetConsentRequest(ctx context.Context, consentChallenge string) (objx.Map, error) {
	return get(ctx, "consent", consentChallenge)
}

func AcceptConsentRequest(ctx context.Context, consentChallenge string, data map[string]interface{}) (objx.Map, error) {

	return put(ctx, "consent", "accept", consentChallenge, data)

}

func RejectConsentRequest(ctx context.Context, consentChallenge string, data map[string]interface{}) (objx.Map, error) {

	return put(ctx, "consent", "reject", consentChallenge, data)

}

func GetLogoutRequest(ctx context.Context, logoutChallenge string) (objx.Map, error) {
	return get(ctx, "logout", logoutChallenge)
}

func AcceptLogoutRequest(ctx context.Context, logoutChallenge string) (objx.Map, error) {

	return put(ctx, "logout", "accept", logoutChallenge, map[string]interface{}{})

}

func RejectLogoutRequest(ctx context.Context, logoutChallenge string, data map[string]interface{}) (objx.Map, error) {

	return put(ctx, "logout", "reject", logoutChallenge, data)

}
