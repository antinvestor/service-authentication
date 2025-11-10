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
	ProfileImage = "ghcr.io/antinvestor/service-profile:latest"
)

type dependency struct {
	*definition.DefaultImpl
}

func NewProfile(containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      ProfileImage,
		Ports:          []string{"50056/tcp", "8086/tcp"},
		NetworkAliases: []string{"profile", "service-profile"},
		UseHostMode:    false,
	}
	opts.Setup(containerOpts...)

	return &dependency{
		DefaultImpl: definition.NewDefaultImpl(opts, ""),
	}
}

func (d *dependency) migrateContainer(
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

func (d *dependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.Opts().Dependencies) != 3 {
		return errors.New("not all expected resource dependencies were supplied, ensure there is a DB, Oauth2 service & Notification container")
	}

	var err error
	databaseURL := ""
	hydraPort := ""
	oauth2ServiceURIAdmin := ""
	partitionService := ""
	notificationService := ""
	for _, dep := range d.Opts().Dependencies {
		if dep.GetDS(ctx).IsDB() {
			databaseURL = dep.GetInternalDS(ctx).String()
		} else {

			if dep.Name() == NotificationImage {
				notificationService = dep.GetInternalDS(ctx).String()
			} else if dep.Name() == PartitionImage {
				partitionService = dep.GetInternalDS(ctx).String()
			} else {

				oauth2ServiceURIAdmin = dep.GetInternalDS(ctx).String()
				hydraPort, err = dep.PortMapping(ctx, "4444")
				if err != nil {
					return err
				}
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
			"HTTP_PORT":                    strings.Replace(d.Opts().Ports[1], "/tcp", "", 1),
			"GRPC_PORT":                    strings.Replace(d.Opts().Ports[0], "/tcp", "", 1),
			"DATABASE_URL":                 databaseURL,
			"CORS_ENABLED":                 "true",
			"CORS_ALLOW_CREDENTIALS":       "true",
			"CORS_ALLOWED_HEADERS":         "Authorization,Content-Type,Origin",
			"CORS_ALLOWED_ORIGINS":         "*",
			"CONTACT_ENCRYPTION_KEY":       "4nbQuIu5ZMa8hvmt66UMZx5gLAI5kdax",
			"CONTACT_ENCRYPTION_SALT":      "geYobar79WDL",
			"OAUTH2_SERVICE_URI":           oauth2ServiceURI,
			"OAUTH2_SERVICE_ADMIN_URI":     oauth2ServiceURIAdmin,
			"OAUTH2_SERVICE_CLIENT_SECRET": "hkGiJroO9cDS5eFnuaAV",
			"OAUTH2_SERVICE_AUDIENCE":      "service_notifications,service_partition",
			"OAUTH2_JWT_VERIFY_AUDIENCE":   "service_profile",
			"OAUTH2_JWT_VERIFY_ISSUER":     "http://127.0.0.1:4444",
			"NOTIFICATION_SERVICE_URI":     notificationService,
			"PARTITION_SERVICE_URI":        partitionService,
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
