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
	DeviceImage = "ghcr.io/antinvestor/service-profile-devices:latest"
)

type deviceDependency struct {
	*definition.DefaultImpl
}

func NewDevice(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      DeviceImage,
		Ports:          []string{"8085/tcp"},
		NetworkAliases: []string{"device", "service-device"},
		UseHostMode:    false,
	}
	opts.Setup(containerOpts...)

	return &deviceDependency{
		DefaultImpl: definition.NewDefaultImpl(opts, "http"),
	}
}

func (d *deviceDependency) migrateContainer(
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

func (d *deviceDependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
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

	// Fetch JWKS from Hydra via the host-mapped port so Docker containers
	// don't need to follow OIDC discovery URLs that use 127.0.0.1.
	jwksData, err := FetchJWKS(ctx, hydraPort)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS for device container: %w", err)
	}

	issuer := fmt.Sprintf("http://127.0.0.1:%s", hydraPort)

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":                    "debug",
			"TRACE_REQUESTS":               "true",
			"DATABASE_LOG_QUERIES":         "true",
			"OPENTELEMETRY_DISABLE":        "true",
			"HTTP_PORT":                    strings.Replace(d.Opts().Ports[0], "/tcp", "", 1),
			"DATABASE_URL":                 databaseURL,
			"OAUTH2_SERVICE_URI":           "http://hydra:4444",
			"OAUTH2_SERVICE_ADMIN_URI":     oauth2ServiceURIAdmin,
			"OAUTH2_SERVICE_CLIENT_SECRET": "hkBaJroO9cDGleFnuaAZ",
			"OAUTH2_SERVICE_AUDIENCE":      "service_notifications,service_tenancy,service_profile,authentication_tests",
			"OAUTH2_JWT_VERIFY_AUDIENCE":   "service_devices",
			"OAUTH2_JWT_VERIFY_ISSUER":     issuer,
			"OAUTH2_WELL_KNOWN_JWK_DATA":   jwksData,
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
