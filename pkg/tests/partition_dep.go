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
	PartitionImage = "ghcr.io/antinvestor/service-authentication-tenancy:latest"
)

type partitionDependancy struct {
	*definition.DefaultImpl
}

func NewPartitionSvc(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      PartitionImage,
		Ports:          []string{"8083/tcp"},
		UseHostMode:    false,
		NetworkAliases: []string{"partition", "service-partition"},
	}
	opts.Setup(containerOpts...)

	return &partitionDependancy{
		DefaultImpl: definition.NewDefaultImpl(opts, "http"),
	}
}

func (d *partitionDependancy) migrateContainer(
	ctx context.Context,
	ntwk *testcontainers.DockerNetwork,
	databaseURL string,
) error {
	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Cmd:   []string{"migrate"},
		Env: map[string]string{
			"LOG_LEVEL":    "debug",
			"DO_MIGRATION": "true",
			"DATABASE_URL": databaseURL,
		},

		WaitingFor: wait.ForExit(),
	}
	d.Configure(ctx, ntwk, &containerRequest)

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest, Started: true,
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

func (d *partitionDependancy) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.Opts().Dependencies) != 2 {
		return errors.New("no Database/ Oauth2 svc dependencies was supplied")
	}

	databaseURL := ""
	hydraPort := ""
	oauth2ServiceURIAdmin := ""
	oauth2ServiceURI := "http://hydra:4444"
	var err error
	for _, dep := range d.Opts().Dependencies {
		if dep.GetDS(ctx).IsDB() {
			if d.Opts().UseHostMode {
				databaseURL = dep.GetDS(ctx).String()
			} else {
				databaseURL = dep.GetInternalDS(ctx).String()
			}
		} else {
			if d.Opts().UseHostMode {
				oauth2ServiceURIAdmin = dep.GetDS(ctx).String()
			} else {
				oauth2ServiceURIAdmin = dep.GetInternalDS(ctx).String()
			}
			hydraPort, err = dep.PortMapping(ctx, "4444/tcp")
			if err != nil {
				return err
			}
			if d.Opts().UseHostMode {
				oauth2ServiceURI = fmt.Sprintf("http://127.0.0.1:%s", hydraPort)
			}
		}
	}

	err = d.migrateContainer(ctx, ntwk, databaseURL)
	if err != nil {
		return err
	}

	jwksData, err := FetchJWKS(ctx, hydraPort)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS for partition container: %w", err)
	}

	issuer := oauth2ServiceURI

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Env: map[string]string{
			"LOG_LEVEL":             "debug",
			"RUN_SERVICE_SECURELY":  "false",
			"TRACE_REQUESTS":        "true",
			"DATABASE_LOG_QUERIES":  "true",
			"OPENTELEMETRY_DISABLE": "true",
			"HTTP_PORT":             strings.Replace(d.Opts().Ports[0], "/tcp", "", 1),
			"DATABASE_URL":          databaseURL,
			"NOTIFICATION_SERVICE_WORKLOAD_API_TARGET_PATH": " ",
			"OAUTH2_SERVICE_URI":                            oauth2ServiceURI,
			"OAUTH2_SERVICE_ADMIN_URI":                      oauth2ServiceURIAdmin,
			"OAUTH2_SERVICE_CLIENT_ID":                      "dev_service_tenancy",
			"OAUTH2_SERVICE_CLIENT_SECRET":                  "hkGiJroO9cDS5eFnuaAV",
			"OAUTH2_TOKEN_ENDPOINT_AUTH_METHOD":             "client_secret_post",
			"OAUTH2_SERVICE_AUDIENCE":                       "service_notifications,service_profile,authentication_tests",
			"OAUTH2_JWT_VERIFY_AUDIENCE":                    "service_tenancy",
			"OAUTH2_JWT_VERIFY_ISSUER":                      issuer,
			"OAUTH2_WELL_KNOWN_JWK_DATA":                    jwksData,
			"SYNCHRONISE_PRIMARY_PARTITIONS":                "true",
		},

		WaitingFor: wait.ForLog("Initiating server operations"),
	}

	d.Configure(ctx, ntwk, &containerRequest)

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
	})

	if err != nil {
		return fmt.Errorf("failed to start genericContainer: %w", err)
	}

	d.SetContainer(genericContainer)
	return nil
}
