package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/docker/go-connections/nat"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	ProfileImage = "ghcr.io/antinvestor/service-profile:latest"
)

type dependency struct {
	opts definition.ContainerOpts

	container testcontainers.Container
}

func NewProfile(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      ProfileImage,
		Ports:          []string{"8085/tcp", "50051/tcp"},
		NetworkAliases: []string{"profile", "service-profile"},
		UseHostMode:    false,
	}
	opts.Setup(containerOpts...)

	return &dependency{
		opts: opts,
	}
}

func (d *dependency) Name() string {
	return d.opts.ImageName
}
func (d *dependency) Container() testcontainers.Container {
	return d.container
}

func (d *dependency) migrateContainer(
	ctx context.Context,
	ntwk *testcontainers.DockerNetwork,
	databaseURL string,
) error {

	containerRequest := testcontainers.ContainerRequest{
		Image: d.opts.ImageName,
		Env: map[string]string{
			"LOG_LEVEL":    "debug",
			"DO_MIGRATION": "true",
			"DATABASE_URL": databaseURL,
		},

		WaitingFor: wait.ForExit(),
	}

	d.opts.Configure(ctx, ntwk, &containerRequest)

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started: true,
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

func (d *dependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.opts.Dependencies) != 2 {
		return errors.New("no Database/ Oauth2 Service dependencies was supplied")
	}

	databaseURL := ""
	oauth2ServiceURIAdmin := ""
	for _, dep := range d.opts.Dependencies {
		if dep.GetDS(ctx).IsDB() {
			databaseURL = dep.GetInternalDS(ctx).String()
		} else {
			oauth2ServiceURIAdmin = dep.GetInternalDS(ctx).String()
		}
	}

	err := d.migrateContainer(ctx, ntwk, databaseURL)
	if err != nil {
		return err
	}

	oauth2ServiceURI := strings.Replace(oauth2ServiceURIAdmin, "4445", "4444", 1)

	containerRequest := testcontainers.ContainerRequest{
		Image: d.opts.ImageName,
		Env: map[string]string{
			"LOG_LEVEL":                    "debug",
			"HTTP_PORT":                    strings.Replace(d.opts.Ports[0], "/tcp", "", 1),
			"GRPC_PORT":                    strings.Replace(d.opts.Ports[1], "/tcp", "", 1),
			"DATABASE_URL":                 databaseURL,
			"CORS_ENABLED":                 "true",
			"CORS_ALLOW_CREDENTIALS":       "true",
			"CORS_ALLOWED_HEADERS":         "Authorization,Content-Type,Origin",
			"CORS_ALLOWED_ORIGINS":         "*",
			"CONTACT_ENCRYPTION_KEY":       "4nbQuIu5ZMa8hvmt66UMZx5gLAI5kdax",
			"CONTACT_ENCRYPTION_SALT":      "geYobar79WDL",
			"OAUTH2_SERVICE_URI":           oauth2ServiceURI,
			"OAUTH2_WELL_KNOWN_JWK":        oauth2ServiceURI + "/.well-known/jwks.json",
			"OAUTH2_SERVICE_ADMIN_URI":     oauth2ServiceURIAdmin,
			"OAUTH2_SERVICE_CLIENT_SECRET": "hkGiJroO9cDS5eFnuaAV",
			"OAUTH2_SERVICE_AUDIENCE":      "service_notifications,service_partition",
			"OAUTH2_JWT_VERIFY_AUDIENCE":   "service_profile",
			"OAUTH2_JWT_VERIFY_ISSUER":     oauth2ServiceURI,
		},
		WaitingFor: wait.ForHTTP("/healthz").WithPort(nat.Port(d.opts.Ports[0])),
	}
	d.opts.Configure(ctx, ntwk, &containerRequest)

	genericContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest, Started: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start genericContainer: %w", err)
	}

	d.container = genericContainer
	return nil
}

func (d *dependency) GetDS(ctx context.Context) frame.DataSource {
	port := nat.Port(d.opts.Ports[1])
	conn, err := d.container.PortEndpoint(ctx, port, "")
	if err != nil {
		logger := util.Log(ctx).WithField("image", d.opts.ImageName)
		logger.WithError(err).Error("failed to get connection for Container")
	}

	return frame.DataSource(conn)
}

func (d *dependency) GetInternalDS(ctx context.Context) frame.DataSource {
	internalIP, err := d.container.ContainerIP(ctx)
	if err != nil {
		logger := util.Log(ctx).WithField("image", d.opts.ImageName)
		logger.WithError(err).Error("failed to get internal host ip for Container")
		return ""
	}

	if internalIP == "" && d.opts.UseHostMode {
		internalIP, err = d.container.Host(ctx)
		if err != nil {
			logger := util.Log(ctx).WithField("image", d.opts.ImageName)
			logger.WithError(err).Error("failed to get host ip for Container")
			return ""
		}
	}
	port := nat.Port(d.opts.Ports[1])

	return frame.DataSource(net.JoinHostPort(internalIP, strconv.Itoa(port.Int())))
}

func (d *dependency) GetRandomisedDS(
	ctx context.Context,
	_ string,
) (frame.DataSource, func(context.Context), error) {
	return d.GetDS(ctx), func(_ context.Context) {
	}, nil
}

func (d *dependency) Cleanup(ctx context.Context) {
	if d.container != nil {
		if err := d.container.Terminate(ctx); err != nil {
			log := util.Log(ctx)
			log.WithError(err).Error("Failed to terminate nats container")
		}
	}
}
