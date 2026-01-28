package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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

func (f *FacebookProvider) AuthCodeURL(state, challenge string) string {
	return f.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (f *FacebookProvider) CompleteLogin(
	ctx context.Context,
	code string,
	verifier string,
) (*AuthenticatedUser, error) {

	token, err := f.oauth2.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("facebook: token exchange failed: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://graph.facebook.com/me?fields=id,name,email",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("facebook: failed to create graph API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook: graph API request failed: %w", err)
	}
	defer resp.Body.Close()

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
