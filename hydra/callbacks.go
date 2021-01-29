package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/antinvestor/service-authentication/config"
	"github.com/go-errors/errors"
	"github.com/pitabwire/frame"
	"github.com/stretchr/objx"
	"io/ioutil"
	"net/http"
	"net/url"
)

func processResp(response *http.Response) (objx.Map, error) {

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	if response.StatusCode != http.StatusOK &&
		response.StatusCode != http.StatusAccepted &&
		response.StatusCode != http.StatusCreated {

		resp, err := objx.FromJSON(string(body))
		if err != nil{
			return nil, errors.Wrap(err, 1)
		}

		return resp, errors.New(response.Status)
	}

	return objx.FromJSON(string(body))

}

// A little helper that takes type (can be "login" or "consent")
// and a challenge and returns the response from ORY Hydra.
func get(flow string, challenge string) (objx.Map, error) {

	params := url.Values{}
	params.Add(fmt.Sprintf("%s_challenge", flow), challenge)

	hydraAdminUrl := frame.GetEnv(config.EnvHydraAdminUri, "http://localhost:4445")
	formatedUrl := fmt.Sprintf("%s/oauth2/auth/requests/%s", hydraAdminUrl, flow)
	baseUrl, err := url.Parse(formatedUrl)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}
	baseUrl.RawQuery = params.Encode()

	response, err := http.Get(baseUrl.String())
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	return processResp(response)
}

// A little helper that takes type (can be "login" or "consent"),
// the action (can be "accept" or "reject") and a challenge
// and returns the response from ORY Hydra.
func put(flow string, action string, challenge string, data map[string]interface{}) (objx.Map, error) {

	params := url.Values{}
	params.Add(fmt.Sprintf("%s_challenge", flow), challenge)

	hydraAdminUrl := frame.GetEnv(config.EnvHydraAdminUri, "http://localhost:4445")
	formatedUrl := fmt.Sprintf("%s/oauth2/auth/requests/%s/%s", hydraAdminUrl, flow, action)
	baseUrl, err := url.Parse(formatedUrl)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}
	baseUrl.RawQuery = params.Encode()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	client := &http.Client{}
	request, err := http.NewRequest(http.MethodPut, baseUrl.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	return processResp(response)

}

func GetLoginRequest(ctx context.Context, loginchallenge string) (objx.Map, error) {

	return get("login", loginchallenge)
}

func AcceptLoginRequest(ctx context.Context, loginchallenge string, data map[string]interface{}) (objx.Map, error) {

	return put("login", "accept", loginchallenge, data)

}

func RejectLoginRequest(ctx context.Context, loginchallenge string, data map[string]interface{}) (objx.Map, error) {

	return put("login", "reject", loginchallenge, data)

}

func GetConsentRequest(ctx context.Context, consentChallenge string) (objx.Map, error) {
	return get("consent", consentChallenge)
}

func AcceptConsentRequest(ctx context.Context, consentChallenge string, data map[string]interface{}) (objx.Map, error) {

	return put("consent", "accept", consentChallenge, data)

}

func RejectConsentRequest(ctx context.Context, consentChallenge string, data map[string]interface{}) (objx.Map, error) {

	return put("consent", "reject", consentChallenge, data)

}

func GetLogoutRequest(ctx context.Context, logoutChallenge string) (objx.Map, error) {
	return get("logout", logoutChallenge)
}

func AcceptLogoutRequest(ctx context.Context, logoutChallenge string) (objx.Map, error) {

	return put("logout", "accept", logoutChallenge, map[string]interface{}{})

}

func RejectLogoutRequest(ctx context.Context, logoutChallenge string, data map[string]interface{}) (objx.Map, error) {

	return put("logout", "reject", logoutChallenge, data)

}
