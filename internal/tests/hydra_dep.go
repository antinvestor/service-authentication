package tests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// HydraImage is the container image name for matching in resource loops.
	HydraImage = "oryd/hydra:latest"
)

// HydraConfiguration is the default Hydra YAML config for tests.
// Callbacks point to http://127.0.0.1:3000 which callers replace with the actual auth service URL.
var HydraConfiguration = testoryhydra.HydraConfiguration

// FetchJWKS fetches the JWKS JSON from a running Hydra instance via its host-mapped port.
func FetchJWKS(ctx context.Context, hostPort string) (string, error) {
	jwksURL := fmt.Sprintf("http://127.0.0.1:%s/.well-known/jwks.json", hostPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching JWKS from %s: %w", jwksURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// hydraDependency wraps frame's testoryhydra to add ExtraHosts support
// and pre-allocated public port for correct OIDC discovery URLs.
type hydraDependency struct {
	*definition.DefaultImpl
	configuration   string
	hostAccessPorts []int
}

// NewHydra creates a Hydra test resource that runs in Docker network mode.
// hostAccessPorts are forwarded from Docker containers to the host via
// testcontainers' SSHD bridge (host.testcontainers.internal).
func NewHydra(configuration string, hostAccessPorts []int, containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      "oryd/hydra:latest",
		Ports:          []string{"4445/tcp", "4444/tcp"},
		NetworkAliases: []string{"hydra", "auth-hydra"},
	}
	opts.Setup(containerOpts...)

	return &hydraDependency{
		DefaultImpl:     definition.NewDefaultImpl(opts, "http"),
		configuration:   configuration,
		hostAccessPorts: hostAccessPorts,
	}
}

func (d *hydraDependency) migrateContainer(
	ctx context.Context,
	ntwk *testcontainers.DockerNetwork,
	databaseURL string,
) error {
	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Cmd:   []string{"migrate", "sql", "up", "--read-from-env", "--yes", "--config", "/etc/config/hydra.yml"},
		Env: map[string]string{
			"LOG_LEVEL": "debug",
			"DSN":       databaseURL,
		},
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader(d.configuration),
				ContainerFilePath: "/etc/config/hydra.yml",
				FileMode:          definition.ContainerFileMode,
			},
		},
		WaitingFor: wait.ForExit(),
	}

	d.Configure(ctx, ntwk, &containerRequest)

	hydraContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
	})
	if err != nil {
		return err
	}

	return hydraContainer.Terminate(ctx)
}

func (d *hydraDependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.Opts().Dependencies) == 0 || !d.Opts().Dependencies[0].GetDS(ctx).IsDB() {
		return errors.New("no database dependency was supplied")
	}

	// Pre-allocate a host port for the public endpoint so the issuer URL is deterministic.
	// OIDC discovery URLs returned by Hydra use the issuer, so the port must match
	// the actual host binding for host-side consumers to follow those URLs.
	publicPort, err := frametests.GetFreePort(ctx)
	if err != nil {
		return fmt.Errorf("failed to allocate public port for hydra: %w", err)
	}

	// Set BOTH issuer and public to the Docker-internal address so that
	// OIDC discovery returns endpoints (including jwks_uri) reachable from
	// containers.  Host-side code sets OAUTH2_WELL_KNOWN_JWK_DATA to skip
	// remote JWKS fetch, and overrides token_endpoint via SetOIDCValue.
	d.configuration = strings.Replace(d.configuration,
		"issuer: http://127.0.0.1:4444", "issuer: http://hydra:4444", 1)
	d.configuration = strings.Replace(d.configuration,
		"public: http://127.0.0.1:4444", "public: http://hydra:4444", 1)

	hydraDatabase, _, err := testpostgres.CreateDatabase(ctx, d.Opts().Dependencies[0].GetInternalDS(ctx), "hydra")
	if err != nil {
		return err
	}

	databaseURL := hydraDatabase.String()
	err = d.migrateContainer(ctx, ntwk, databaseURL)
	if err != nil {
		return err
	}

	publicPortStr := strconv.Itoa(publicPort)
	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Cmd:   []string{"serve", "all", "--config", "/etc/config/hydra.yml", "--dev"},
		Env: d.Opts().Env(map[string]string{
			"LOG_LEVEL":                 "debug",
			"LOG_LEAK_SENSITIVE_VALUES": "true",
			"DSN":                       databaseURL,
		}),
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader(d.configuration),
				ContainerFilePath: "/etc/config/hydra.yml",
				FileMode:          definition.ContainerFileMode,
			},
		},
		HostAccessPorts: d.hostAccessPorts,
		WaitingFor:      wait.ForHTTP("/health/ready").WithPort(d.DefaultPort),
		HostConfigModifier: func(hostConfig *container.HostConfig) {
			// Bind the public port (4444) to the pre-allocated host port
			// so OIDC discovery URLs match the actual host port.
			if hostConfig.PortBindings == nil {
				hostConfig.PortBindings = nat.PortMap{}
			}
			hostConfig.PortBindings["4444/tcp"] = []nat.PortBinding{
				{HostIP: "0.0.0.0", HostPort: publicPortStr},
			}
		},
	}

	d.Configure(ctx, ntwk, &containerRequest)

	hydraContainer, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: containerRequest,
			Started:          true,
		})

	if err != nil {
		return fmt.Errorf("failed to start hydraContainer: %w", err)
	}

	d.SetContainer(hydraContainer)
	return nil
}
