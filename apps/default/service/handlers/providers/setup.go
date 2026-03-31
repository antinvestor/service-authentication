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

	if cfg.AuthProviderGoogleClientID != "" {
		p, err := NewGoogleOIDCProvider(
			ctx,
			cfg.AuthProviderGoogleClientID,
			cfg.AuthProviderGoogleSecret,
			cfg.AuthProviderGoogleCallbackURL,
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
