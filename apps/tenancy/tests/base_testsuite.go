package tests

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/stretchr/testify/require"
)

type BaseTestSuite struct {
	internaltests.BaseTestSuite
}

func initResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_tenancy",
		definition.WithUserName("ant"), definition.WithPassword("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	hydra := testoryhydra.NewWithOpts(
		testoryhydra.HydraConfiguration, definition.WithDependancies(pg),
		definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	auth := internaltests.NewAuthentication(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	resources := []definition.TestResource{pg, hydra, auth}
	return resources
}

func (bs *BaseTestSuite) SetupSuite() {

	bs.InitResourceFunc = initResources
	bs.BaseTestSuite.SetupSuite()
}

func (bs *BaseTestSuite) CreateService(
	t *testing.T,
	depOpts *definition.DependancyOption,
) (*frame.Service, context.Context) {

	ctx := t.Context()

	var databaseDR definition.DependancyConn
	var hydraDR definition.DependancyConn
	// var authenticationDR definition.DependancyConn
	for _, res := range bs.Resources() {
		switch res.Name() {
		case testpostgres.PostgresqlDBImage:
			databaseDR = res
		// case internaltests.AuthenticationImage:
		// 	authenticationDR = res
		case testoryhydra.OryHydraImage:
			hydraDR = res
		}
	}

	testDS, cleanup, err0 := databaseDR.GetRandomisedDS(ctx, depOpts.Prefix())
	require.NoError(t, err0)
	t.Cleanup(func() {
		cleanup(ctx)
	})

	hydraPort, err := hydraDR.PortMapping(ctx, "4444/tcp")
	require.NoError(t, err)

	oauth2ServiceURI, err := hydraDR.GetDS(ctx).ChangePort(hydraPort)
	require.NoError(t, err)

	t.Setenv("OAUTH2_SERVICE_URI", oauth2ServiceURI.String())

	cfg, err := frame.ConfigLoadWithOIDC[config.PartitionConfig](ctx)
	require.NoError(t, err)

	cfg.LogLevel = "debug"
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}
	cfg.Oauth2ServiceAdminURI = hydraDR.GetDS(ctx).String()

	ctx, svc := frame.NewServiceWithContext(ctx, "tenancy tests",
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
