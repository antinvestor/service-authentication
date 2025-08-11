package tests

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/stretchr/testify/require"
)

type BaseTestSuite struct {
	internaltests.BaseTestSuite
}

func (bs *BaseTestSuite) CreateService(
	t *testing.T,
	depOpts *definition.DependancyOption,
) (*frame.Service, context.Context) {
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	cfg, err := frame.ConfigFromEnv[config.PartitionConfig]()
	require.NoError(t, err)

	cfg.LogLevel = "debug"
	cfg.RunServiceSecurely = false
	cfg.ServerPort = ""

	ctx := t.Context()
	for _, res := range depOpts.Database(ctx) {
		testDS, cleanup, err0 := res.GetRandomisedDS(t.Context(), depOpts.Prefix())
		require.NoError(t, err0)

		t.Cleanup(func() {
			cleanup(t.Context())
		})

		cfg.DatabasePrimaryURL = []string{testDS.String()}
		cfg.DatabaseReplicaURL = []string{testDS.String()}
	}

	ctx, svc := frame.NewServiceWithContext(ctx, "partition tests",
		frame.WithConfig(&cfg),
		frame.WithDatastore(),
		frame.WithNoopDriver())

	svc.Init(ctx)

	err = repository.Migrate(ctx, svc, "../../migrations/0001")
	require.NoError(t, err)

	err = svc.Run(ctx, "")
	require.NoError(t, err)

	return svc, ctx
}
