package tests

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	AuthenticationImage = "ghcr.io/antinvestor/service-authentication:latest"
)

type authenticationDependency struct {
	*definition.DefaultImpl
}

func NewAuthentication(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      AuthenticationImage,
		Ports:          []string{"8081/tcp"},
		NetworkAliases: []string{"device", "service-device"},
		UseHostMode:    false,
	}
	opts.Setup(containerOpts...)

	return &authenticationDependency{
		DefaultImpl: definition.NewDefaultImpl(opts, ""),
	}
}

func (d *authenticationDependency) migrateContainer(
	ctx context.Context,
	ntwk *testcontainers.DockerNetwork,
	databaseURL string,
) error {

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":    "debug",
			"DO_MIGRATION": "true",
			"DATABASE_URL": databaseURL,
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

func (d *authenticationDependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.Opts().Dependencies) != 2 {
		return errors.New("no Database/ Oauth2 svc dependencies was supplied")
	}

	var err error
	databaseURL := ""
	hydraPort := ""
	var oauth2ServiceURIAdmin frame.DataSource
	for _, dep := range d.Opts().Dependencies {
		if dep.GetDS(ctx).IsDB() {
			databaseURL = dep.GetInternalDS(ctx).String()
		} else {
			oauth2ServiceURIAdmin = dep.GetInternalDS(ctx)
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

	oauth2ServiceURI, err := oauth2ServiceURIAdmin.ChangePort(hydraPort)
	if err != nil {
		return err
	}

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":                    "debug",
			"HTTP_PORT":                    strings.Replace(d.Opts().Ports[0], "/tcp", "", 1),
			"DATABASE_URL":                 databaseURL,
			"OAUTH2_SERVICE_URI":           oauth2ServiceURI.String(),
			"OAUTH2_SERVICE_ADMIN_URI":     oauth2ServiceURIAdmin.String(),
			"OAUTH2_SERVICE_CLIENT_SECRET": "hkCyJroO9cDGleFnuaAZ",
			"OAUTH2_SERVICE_AUDIENCE":      "service_notifications,service_partition,service_profile,service_authentication",
			"OAUTH2_JWT_VERIFY_AUDIENCE":   "service_tenancy",
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
