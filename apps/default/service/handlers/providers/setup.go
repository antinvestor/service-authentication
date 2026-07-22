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
	"fmt"

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/pitabwire/util"
)

func SetupAuthProviders(ctx context.Context, cfg *config.AuthenticationConfig) (map[string]AuthProvider, error) {
	log := util.Log(ctx)
	providers := map[string]AuthProvider{}
	// One shared timed client for all external IdP HTTP (token exchange, OIDC).
	idpHTTP := newExternalIDPHTTPClient(ctx)

	if cfg.GoogleLoginConfigured() {
		p, err := NewGoogleOIDCProvider(
			ctx,
			cfg.AuthProviderGoogleClientID,
			cfg.AuthProviderGoogleSecret,
			cfg.AuthProviderGoogleCallbackURL,
			idpHTTP,
		)
		if err != nil {
			return nil, fmt.Errorf("google provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderGoogleCallbackURL).Debug("Google OIDC provider initialised")
	}

	if cfg.AuthProviderMetaClientID != "" {
		p, err := NewFacebookProvider(
			cfg.AuthProviderMetaClientID,
			cfg.AuthProviderMetaSecret,
			cfg.AuthProviderMetaCallbackURL,
			cfg.AuthProviderMetaScopes,
			idpHTTP,
		)
		if err != nil {
			return nil, fmt.Errorf("facebook provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderMetaCallbackURL).Debug("Facebook provider initialised")
	}

	if cfg.AuthProviderAppleClientID != "" {
		p, err := NewAppleProvider(
			ctx,
			cfg.AuthProviderAppleClientID,
			cfg.AuthProviderAppleCallbackURL,
			cfg.AuthProviderAppleClientSecretJWT,
			idpHTTP,
		)
		if err != nil {
			return nil, fmt.Errorf("apple provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderAppleCallbackURL).Debug("Apple provider initialised")
	}

	if cfg.AuthProviderMicrosoftClientID != "" {
		p, err := NewMicrosoftProvider(
			ctx,
			cfg.AuthProviderMicrosoftTenant,
			cfg.AuthProviderMicrosoftClientID,
			cfg.AuthProviderMicrosoftSecret,
			cfg.AuthProviderMicrosoftCallbackURL,
			idpHTTP,
		)
		if err != nil {
			return nil, fmt.Errorf("microsoft provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderMicrosoftCallbackURL).Debug("Microsoft provider initialised")
	}

	log.WithField("provider_count", len(providers)).Info("auth provider setup complete")
	return providers, nil
}
