package config

import "github.com/pitabwire/frame"

type AuthenticationConfig struct {
	frame.ConfigurationDefault

	Oauth2ServiceAdminURI string `default:"http://localhost:4445" envconfig:"OAUTH2_SERVICE_ADMIN_URI"`
	PartitionServiceURI   string `default:"127.0.0.1:7003" envconfig:"PARTITION_SERVICE_URI"`
	ProfileServiceURI     string `default:"127.0.0.1:7020" envconfig:"PROFILE_SERVICE_URI"`

	CsrfSecret string `default:"\\xf80105efab6d863fd8fc243d269094469e2277e8f12e5a0a9f401e88494f7b4b" envconfig:"CSRF_SECRET"`
}
