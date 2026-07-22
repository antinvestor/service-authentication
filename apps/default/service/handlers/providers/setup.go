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

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/pitabwire/util"
)

// SetupAuthProviders registers configured social login providers.
//
// Per-provider failures are logged and skipped so one broken IdP (e.g. Google
// discovery timeout at cold start) cannot disable every other provider for the
// lifetime of the process.
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
			log.WithError(err).Error("google provider setup failed — google login unavailable until restart")
		} else {
			providers[p.Name()] = p
			log.WithField("callback_url", cfg.AuthProviderGoogleCallbackURL).Info("Google OIDC provider registered")
		}
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
			log.WithError(err).Error("facebook provider setup failed — facebook login unavailable until restart")
		} else {
			providers[p.Name()] = p
			log.WithField("callback_url", cfg.AuthProviderMetaCallbackURL).Info("Facebook provider registered")
		}
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
			log.WithError(err).Error("apple provider setup failed — apple login unavailable until restart")
		} else {
			providers[p.Name()] = p
			log.WithField("callback_url", cfg.AuthProviderAppleCallbackURL).Info("Apple provider registered")
		}
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
			log.WithError(err).Error("microsoft provider setup failed — microsoft login unavailable until restart")
		} else {
			providers[p.Name()] = p
			log.WithField("callback_url", cfg.AuthProviderMicrosoftCallbackURL).Info("Microsoft provider registered")
		}
	}

	log.WithField("provider_count", len(providers)).Info("auth provider setup complete")
	return providers, nil
}
