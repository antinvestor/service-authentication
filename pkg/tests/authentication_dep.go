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
	AuthenticationImage = "ghcr.io/antinvestor/service-authentication:latest"
)

type authenticationDependency struct {
	*definition.DefaultImpl
}

func NewAuthentication(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      AuthenticationImage,
		Ports:          []string{"8081/tcp"},
		NetworkAliases: []string{"authentication", "service-authentication"},
		UseHostMode:    false,
	}
	opts.Setup(containerOpts...)

	return &authenticationDependency{
		DefaultImpl: definition.NewDefaultImpl(opts, "http"),
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

	databaseURL := ""
	hydraPort := ""
	oauth2ServiceURIAdmin := ""
	var err error
	for _, dep := range d.Opts().Dependencies {
		if dep.GetDS(ctx).IsDB() {
			databaseURL = dep.GetInternalDS(ctx).String()
		} else {
			oauth2ServiceURIAdmin = dep.GetInternalDS(ctx).String()
			hydraPort, err = dep.PortMapping(ctx, "4444/tcp")
			if err != nil {
				return err
			}
		}
	}

	err = d.migrateContainer(ctx, ntwk, databaseURL)
	if err != nil {
		return err
	}

	jwksData, err := FetchJWKS(ctx, hydraPort)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS for authentication container: %w", err)
	}

	issuer := "http://hydra:4444"

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":            "debug",
			"TRACE_REQUESTS":       "true",
			"DATABASE_LOG_QUERIES": "true",
			"HTTP_PORT":            strings.Replace(d.Opts().Ports[0], "/tcp", "", 1),
			"DATABASE_URL":         databaseURL,
			"PARTITION_SERVICE_WORKLOAD_API_TARGET_PATH":    " ",
			"PROFILE_SERVICE_WORKLOAD_API_TARGET_PATH":      " ",
			"DEVICE_SERVICE_WORKLOAD_API_TARGET_PATH":       " ",
			"NOTIFICATION_SERVICE_WORKLOAD_API_TARGET_PATH": " ",
			"OAUTH2_SERVICE_URI":                            "http://hydra:4444",
			"OAUTH2_SERVICE_ADMIN_URI":                      oauth2ServiceURIAdmin,
			"OAUTH2_SERVICE_CLIENT_SECRET":                  "hkCyJroO9cDGleFnuaAZ",
			"OAUTH2_SERVICE_AUDIENCE":                       "service_devices,service_notifications,service_tenancy,service_profile",
			"OAUTH2_JWT_VERIFY_AUDIENCE":                    "service_tenancy,authentication_tests",
			"OAUTH2_JWT_VERIFY_ISSUER":                      issuer,
			"OAUTH2_WELL_KNOWN_JWK_DATA":                    jwksData,
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
