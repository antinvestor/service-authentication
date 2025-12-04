package tests

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pitabwire/frame/frametests/definition"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	NotificationImage = "ghcr.io/antinvestor/service-notification:latest"
)

type notificationDependancy struct {
	*definition.DefaultImpl
}

func NewNotificationSvc(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      NotificationImage,
		Ports:          []string{"8087/tcp"},
		UseHostMode:    false,
		NetworkAliases: []string{"notification", "service-notification"},
	}
	opts.Setup(containerOpts...)

	return &notificationDependancy{
		DefaultImpl: definition.NewDefaultImpl(opts, "http"),
	}
}

func (d *notificationDependancy) migrateContainer(
	ctx context.Context,
	ntwk *testcontainers.DockerNetwork,
	databaseURL string,
) error {

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":            "debug",
			"DO_MIGRATION":         "true",
			"DATABASE_LOG_QUERIES": "true",
			"DATABASE_URL":         databaseURL,
		},

		WaitingFor: wait.ForExit(),
	}

	d.Configure(ctx, ntwk, &containerRequest)

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
	})
	if err != nil {
		return err
	}

	err = genericContainer.Terminate(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (d *notificationDependancy) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.Opts().Dependencies) != 2 {
		return errors.New("no Database/ Oauth2 svc dependencies was supplied")
	}

	var err error
	databaseURL := ""
	hydraPort := ""
	oauth2ServiceURIAdmin := ""
	for _, dep := range d.Opts().Dependencies {
		if dep.GetDS(ctx).IsDB() {
			databaseURL = dep.GetInternalDS(ctx).String()
		} else {
			oauth2ServiceURIAdmin = dep.GetInternalDS(ctx).String()
			hydraPort, err = dep.PortMapping(ctx, "4444")
			if err != nil {
				return err
			}
		}
	}

	err = d.migrateContainer(ctx, ntwk, databaseURL)
	if err != nil {
		return err
	}

	// Convert admin URI to public URI by changing port
	oauth2ServiceURI := strings.Replace(oauth2ServiceURIAdmin, "4445", hydraPort, 1)

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":                    "debug",
			"TRACE_REQUESTS":               "true",
			"DATABASE_LOG_QUERIES":         "true",
			"OPENTELEMETRY_DISABLE":        "true",
			"HTTP_PORT":                    strings.Replace(d.Opts().Ports[0], "/tcp", "", 1),
			"DATABASE_URL":                 databaseURL,
			"CORS_ENABLED":                 "true",
			"CORS_ALLOW_CREDENTIALS":       "true",
			"CORS_ALLOWED_HEADERS":         "Authorization,Content-Type,Origin",
			"CORS_ALLOWED_ORIGINS":         "*",
			"OAUTH2_SERVICE_URI":           oauth2ServiceURI,
			"OAUTH2_SERVICE_ADMIN_URI":     oauth2ServiceURIAdmin,
			"OAUTH2_SERVICE_CLIENT_SECRET": "hkGiJroO9cDS5eFnuaAV",
			"OAUTH2_SERVICE_AUDIENCE":      "service_profile,service_tenancy,service_devices",
			"OAUTH2_JWT_VERIFY_AUDIENCE":   "service_notifications",
			"OAUTH2_JWT_VERIFY_ISSUER":     "http://127.0.0.1:4444",
		},

		WaitingFor: wait.ForLog("Initiating server operations"),
	}

	d.Configure(ctx, ntwk, &containerRequest)

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest, Started: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start genericContainer: %w", err)
	}

	d.SetContainer(genericContainer)
	return nil
}
