// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pitabwire/util"
	"golang.org/x/oauth2"
)

type FacebookProvider struct {
	oauth2 oauth2.Config
}

func NewFacebookProvider(
	clientID, clientSecret, redirectURL string,
	scopes []string,
) (*FacebookProvider, error) {
	return &FacebookProvider{
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://www.facebook.com/v18.0/dialog/oauth",
				TokenURL: "https://graph.facebook.com/v18.0/oauth/access_token",
			},
			Scopes: scopes,
		},
	}, nil
}

func (f *FacebookProvider) Name() string {
	return "facebook"
}

func (f *FacebookProvider) AuthCodeURL(state, challenge, nonce string) string {
	authURL := f.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	if nonce != "" {
		authURL = f.oauth2.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("nonce", nonce),
		)
	}
	return authURL
}

func (f *FacebookProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
	_ string,
) (*AuthenticatedUser, error) {

	token, err := f.oauth2.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("facebook: token exchange failed: %w", err)
	}

	return f.fetchUserByAccessToken(ctx, token.AccessToken)
}

// VerifyNativeToken verifies a Facebook user access token obtained by the
// mobile SDK. The token is validated by calling the Graph API /me endpoint
// and checking the app_id via the debug_token endpoint.
func (f *FacebookProvider) VerifyNativeToken(ctx context.Context, rawToken string) (*AuthenticatedUser, error) {
	if err := f.validateTokenAppID(ctx, rawToken); err != nil {
		return nil, err
	}
	return f.fetchUserByAccessToken(ctx, rawToken)
}

// validateTokenAppID checks that the access token was issued for this app
// by calling the Facebook debug_token endpoint.
func (f *FacebookProvider) validateTokenAppID(ctx context.Context, accessToken string) error {
	appToken := f.oauth2.ClientID + "|" + f.oauth2.ClientSecret
	debugURL := fmt.Sprintf(
		"https://graph.facebook.com/debug_token?input_token=%s&access_token=%s",
		accessToken, appToken,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, debugURL, nil)
	if err != nil {
		return fmt.Errorf("facebook: failed to create debug_token request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("facebook: debug_token request failed: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("facebook: debug_token returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			AppID   string `json:"app_id"`
			IsValid bool   `json:"is_valid"`
		} `json:"data"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("facebook: failed to decode debug_token response: %w", err)
	}

	if !result.Data.IsValid {
		return fmt.Errorf("facebook: access token is not valid")
	}

	if result.Data.AppID != f.oauth2.ClientID {
		return fmt.Errorf("facebook: token app_id %q does not match configured client_id", result.Data.AppID)
	}

	return nil
}

func (f *FacebookProvider) fetchUserByAccessToken(ctx context.Context, accessToken string) (*AuthenticatedUser, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://graph.facebook.com/me?fields=id,name,email",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("facebook: failed to create graph API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook: graph API request failed: %w", err)
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook: graph API returned HTTP %d", resp.StatusCode)
	}

	var data map[string]any
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("facebook: failed to decode graph API response: %w", err)
	}

	email, _ := data["email"].(string)
	name, _ := data["name"].(string)

	return &AuthenticatedUser{
		Contact: email,
		Name:    name,
		Raw:     data,
	}, nil
}
