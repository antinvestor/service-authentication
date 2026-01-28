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
		log.Info("initialising Google OIDC provider")
		p, err := NewGoogleOIDCProvider(
			ctx,
			cfg.AuthProviderGoogleClientID,
			cfg.AuthProviderGoogleSecret,
			cfg.AuthProviderGoogleCallbackURL,
		)
		if err != nil {
			log.WithError(err).Error("failed to initialise Google OIDC provider")
			return nil, fmt.Errorf("google provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderGoogleCallbackURL).Info("Google OIDC provider initialised")
	}

	if cfg.AuthProviderMetaClientID != "" {
		log.Info("initialising Facebook provider")
		p, err := NewFacebookProvider(
			cfg.AuthProviderMetaClientID,
			cfg.AuthProviderMetaSecret,
			cfg.AuthProviderMetaCallbackURL,
			cfg.AuthProviderMetaScopes,
		)
		if err != nil {
			log.WithError(err).Error("failed to initialise Facebook provider")
			return nil, fmt.Errorf("facebook provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderMetaCallbackURL).Info("Facebook provider initialised")
	}

	if cfg.AuthProviderAppleClientID != "" {
		log.Info("initialising Apple provider")
		p, err := NewAppleProvider(
			ctx,
			cfg.AuthProviderAppleClientID,
			cfg.AuthProviderAppleCallbackURL,
			cfg.AuthProviderAppleClientSecretJWT,
		)
		if err != nil {
			log.WithError(err).Error("failed to initialise Apple provider")
			return nil, fmt.Errorf("apple provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderAppleCallbackURL).Info("Apple provider initialised")
	}

	if cfg.AuthProviderMicrosoftClientID != "" {
		log.WithField("tenant", cfg.AuthProviderMicrosoftTenant).Info("initialising Microsoft provider")
		p, err := NewMicrosoftProvider(
			ctx,
			cfg.AuthProviderMicrosoftTenant,
			cfg.AuthProviderMicrosoftClientID,
			cfg.AuthProviderMicrosoftSecret,
			cfg.AuthProviderMicrosoftCallbackURL,
		)
		if err != nil {
			log.WithError(err).Error("failed to initialise Microsoft provider")
			return nil, fmt.Errorf("microsoft provider setup failed: %w", err)
		}
		providers[p.Name()] = p
		log.WithField("callback_url", cfg.AuthProviderMicrosoftCallbackURL).Info("Microsoft provider initialised")
	}

	log.WithField("provider_count", len(providers)).Info("v2 auth provider setup complete")
	return providers, nil
}
