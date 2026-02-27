package testketo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// ImageName is the Ory Keto image used for test containers.
	ImageName = "oryd/keto:latest"

	ketoConfiguration = `
limit:
  max_read_depth: 10

serve:
  read:
    host: 0.0.0.0
    port: 4466
  write:
    host: 0.0.0.0
    port: 4467

log:
  level: debug
  format: text

namespaces:
  location: file:///home/ory/namespaces/tenancy.ts

`

	oplNamespaces = `import { Namespace, Context } from "@ory/keto-namespace-types"

class profile_user implements Namespace {}

class tenancy_access implements Namespace {
  related: {
    member: (profile_user | tenancy_access)[]
    service: profile_user[]
  }
}

class service_tenancy implements Namespace {
  related: {
    owner: profile_user[]
    admin: profile_user[]
    member: profile_user[]
    service: (profile_user | tenancy_access)[]

    // Direct permission grants (accept service_tenancy subject sets for service role bridging)
    manage_tenant: (profile_user | service_tenancy)[]
    view_tenant: (profile_user | service_tenancy)[]
    manage_partition: (profile_user | service_tenancy)[]
    view_partition: (profile_user | service_tenancy)[]
    manage_access: (profile_user | service_tenancy)[]
    view_access: (profile_user | service_tenancy)[]
    manage_roles: (profile_user | service_tenancy)[]
    manage_pages: (profile_user | service_tenancy)[]
    view_pages: (profile_user | service_tenancy)[]
    grant_permission: (profile_user | service_tenancy)[]
  }

  permits = {
    manage_tenant: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.manage_tenant.includes(ctx.subject),

    view_tenant: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_tenant(ctx) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_tenant.includes(ctx.subject),

    manage_partition: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_partition.includes(ctx.subject),

    view_partition: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_partition(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_partition.includes(ctx.subject),

    manage_access: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_access.includes(ctx.subject),

    view_access: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_access(ctx) ||
      this.related.view_access.includes(ctx.subject),

    manage_roles: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_roles.includes(ctx.subject),

    manage_pages: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_pages.includes(ctx.subject),

    view_pages: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_pages(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_pages.includes(ctx.subject),

    grant_permission: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.grant_permission.includes(ctx.subject),
  }
}
`

	namespaceFile = "/home/ory/namespaces/tenancy.ts"
)

type dependency struct {
	*definition.DefaultImpl
}

// NewWithOpts creates a new Keto test resource with OPL namespace support.
func NewWithOpts(
	containerOpts ...definition.ContainerOption,
) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      ImageName,
		Ports:          []string{"4467/tcp", "4466/tcp"},
		NetworkAliases: []string{"keto", "auth-keto"},
	}
	opts.Setup(containerOpts...)

	return &dependency{
		DefaultImpl: definition.NewDefaultImpl(opts, "http"),
	}
}

func (d *dependency) migrateContainer(
	ctx context.Context,
	ntwk *testcontainers.DockerNetwork,
	databaseURL string,
) error {
	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Cmd:   []string{"migrate", "up", "--yes"},
		Env: map[string]string{
			"LOG_LEVEL": "debug",
			"DSN":       databaseURL,
		},
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader(ketoConfiguration),
				ContainerFilePath: "/home/ory/keto.yml",
				FileMode:          definition.ContainerFileMode,
			},
			{
				Reader:            strings.NewReader(oplNamespaces),
				ContainerFilePath: namespaceFile,
				FileMode:          definition.ContainerFileMode,
			},
		},
		WaitingFor: wait.ForExit(),
	}

	d.Configure(ctx, ntwk, &containerRequest)

	ketoContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start keto migration container: %w", err)
	}

	if err = ketoContainer.Terminate(ctx); err != nil {
		return fmt.Errorf("failed to terminate keto migration container: %w", err)
	}
	return nil
}

func (d *dependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	if len(d.Opts().Dependencies) == 0 || !d.Opts().Dependencies[0].GetDS(ctx).IsDB() {
		return errors.New("no database dependency was supplied")
	}

	ketoDB, _, err := testpostgres.CreateDatabase(ctx, d.Opts().Dependencies[0].GetInternalDS(ctx), "keto")
	if err != nil {
		return fmt.Errorf("failed to create keto database: %w", err)
	}

	databaseURL := ketoDB.String()

	if err = d.migrateContainer(ctx, ntwk, databaseURL); err != nil {
		return err
	}

	containerRequest := testcontainers.ContainerRequest{
		Image: d.Name(),
		Cmd:   []string{"serve", "--config", "/home/ory/keto.yml"},
		Env: d.Opts().Env(map[string]string{
			"LOG_LEVEL":                 "debug",
			"LOG_LEAK_SENSITIVE_VALUES": "true",
			"DSN":                       databaseURL,
		}),
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader(ketoConfiguration),
				ContainerFilePath: "/home/ory/keto.yml",
				FileMode:          definition.ContainerFileMode,
			},
			{
				Reader:            strings.NewReader(oplNamespaces),
				ContainerFilePath: namespaceFile,
				FileMode:          definition.ContainerFileMode,
			},
		},
		WaitingFor: wait.ForHTTP("/health/ready").WithPort(d.DefaultPort),
	}

	d.Configure(ctx, ntwk, &containerRequest)

	ketoContainer, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: containerRequest,
			Started:          true,
		})
	if err != nil {
		return fmt.Errorf("failed to start keto serve container: %w", err)
	}

	d.SetContainer(ketoContainer)
	return nil
}
