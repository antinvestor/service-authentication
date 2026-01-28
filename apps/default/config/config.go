package config

import (
	"github.com/pitabwire/frame/config"
)

type AuthenticationConfig struct {
	config.ConfigurationDefault

	// Error handling configuration
	// When true, detailed error messages are shown to users (useful for development)
	// When false, generic messages are shown and details are only logged
	ExposeErrors bool `envDefault:"false" env:"EXPOSE_ERRORS"`

	// Cache configuration (Redis or similar)
	CacheName            string `envDefault:"defaultCache"           env:"CACHE_NAME"`
	CacheURI             string `envDefault:"mem://defaultCache" env:"CACHE_URI"`
	CacheCredentialsFile string `envDefault:""                       env:"CACHE_CREDENTIALS_FILE"`

	SessionRememberDuration int64  `envDefault:"7776000" env:"SESSION_REMEMBER_DURATION"`
	PartitionServiceURI     string `envDefault:"127.0.0.1:7003" env:"PARTITION_SERVICE_URI"`
	ProfileServiceURI       string `envDefault:"127.0.0.1:7020" env:"PROFILE_SERVICE_URI"`
	DeviceServiceURI        string `envDefault:"127.0.0.1:7020" env:"DEVICE_SERVICE_URI"`
	NotificationServiceURI  string `envDefault:"127.0.0.1:7020" env:"NOTIFICATION_SERVICE_URI"`

	HydraWebhookAPIToken string `envDefault:"" env:"HYDRA_WEBHOOK_API_PSK"`

	SecureCookieHashKey  string `envDefault:"d1f4f1a3b8d84f79e6d4b8b5c3f04725a8a7d6b4c2f9a987d5e4f3a2b1c086d1" env:"SECURE_COOKIE_HASH_KEY"`
	SecureCookieBlockKey string `envDefault:"a7e7b4f8d2e5a3c1f0b6d9d4f3a5c20798d1c1e7c4f6a3e4b0e5c2f4a7d6b301" env:"SECURE_COOKIE_BLOCK_KEY"`

	AuthProviderContactLoginDisabled                bool     `envDefault:"false" env:"AUTH_PROVIDER_CONTACT_LOGIN_DISABLED"`
	AuthProviderContactLoginMaxVerificationAttempts int      `envDefault:"3" env:"AUTH_PROVIDER_CONTACT_LOGIN_MAX_VERIFICATION_ATTEMPTS"`
	AuthProviderSessionAge                          int      `envDefault:"5184000"  env:"AUTH_PROVIDER_SESSION_AGE"`
	AuthProviderGoogleClientID                      string   `envDefault:"" env:"AUTH_PROVIDER_GOOGLE_CLIENT_ID"`
	AuthProviderGoogleSecret                        string   `envDefault:"" env:"AUTH_PROVIDER_GOOGLE_SECRET"`
	AuthProviderGoogleCallbackURL                   string   `envDefault:"" env:"AUTH_PROVIDER_GOOGLE_CALLBACK_URL"`
	AuthProviderGoogleScopes                        []string `envDefault:"" env:"AUTH_PROVIDER_GOOGLE_SCOPES"`

	AuthProviderMetaClientID    string   `envDefault:"" env:"AUTH_PROVIDER_META_CLIENT_ID"`
	AuthProviderMetaSecret      string   `envDefault:"" env:"AUTH_PROVIDER_META_SECRET"`
	AuthProviderMetaCallbackURL string   `envDefault:"" env:"AUTH_PROVIDER_META_CALLBACK_URL"`
	AuthProviderMetaScopes      []string `envDefault:"" env:"AUTH_PROVIDER_META_SCOPES"`

	AuthProviderAppleClientID        string `envDefault:"" env:"AUTH_PROVIDER_APPLE_CLIENT_ID"`
	AuthProviderAppleClientSecretJWT string `envDefault:"" env:"AUTH_PROVIDER_APPLE_CLIENT_SECRET_JWT"`
	AuthProviderAppleCallbackURL     string `envDefault:"" env:"AUTH_PROVIDER_APPLE_CALLBACK_URL"`

	AuthProviderMicrosoftTenant      string `envDefault:"common" env:"AUTH_PROVIDER_MICROSOFT_TENANT"`
	AuthProviderMicrosoftClientID    string `envDefault:"" env:"AUTH_PROVIDER_MICROSOFT_CLIENT_ID"`
	AuthProviderMicrosoftSecret      string `envDefault:"" env:"AUTH_PROVIDER_MICROSOFT_SECRET"`
	AuthProviderMicrosoftCallbackURL string `envDefault:"" env:"AUTH_PROVIDER_MICROSOFT_CALLBACK_URL"`
}
