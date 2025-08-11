package tests

import (
	"context"
	"testing"

	apis "github.com/antinvestor/apis/go/common"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	handlers2 "github.com/gorilla/handlers"
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
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithPassword("s3cr3t"),
		definition.WithEnableLogging(true), definition.WithUseHostMode(false))
	hydra := testoryhydra.NewWithOpts(
		testoryhydra.HydraConfiguration, definition.WithDependancies(pg),
		definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	// Add profile and partition service dependencies
	profile := NewProfile(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))
	partition := NewPartitionSvc(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))

	resources := []definition.TestResource{pg, hydra, profile, partition}
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
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	cfg, err := frame.ConfigFromEnv[config.AuthenticationConfig]()
	require.NoError(t, err)

	ctx := t.Context()

	cfg.LogLevel = "debug"
	cfg.RunServiceSecurely = false
	cfg.ServerPort = ""

	var databaseDR definition.DependancyConn
	var hydraDR definition.DependancyConn
	var profileDR definition.DependancyConn
	var partitionDR definition.DependancyConn
	for _, res := range bs.Resources() {
		switch res.Name() {
		case testpostgres.PostgresqlDBImage:
			databaseDR = res
		case ProfileImage:
			profileDR = res
		case PartitionImage:
			partitionDR = res
		case testoryhydra.OryHydraImage:
			hydraDR = res
		}
	}

	testDS, cleanup, err0 := databaseDR.GetRandomisedDS(ctx, depOpts.Prefix())
	require.NoError(t, err0)
	t.Cleanup(func() {
		cleanup(ctx)
	})

	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}

	cfg.PartitionServiceURI = partitionDR.GetDS(ctx).String()
	cfg.ProfileServiceURI = profileDR.GetDS(ctx).String()
	cfg.Oauth2ServiceURI = hydraDR.GetDS(ctx).String()

	ctx, svc := frame.NewServiceWithContext(t.Context(), "authentication tests",
		frame.WithConfig(&cfg),
		frame.WithDatastore(),
		frame.WithNoopDriver())

	partitionCli, err := partitionv1.NewPartitionsClient(ctx,
		apis.WithEndpoint(cfg.PartitionServiceURI),
		apis.WithTokenEndpoint(cfg.Oauth2ServiceURI),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(cfg.Oauth2ServiceClientSecret),
		apis.WithAudiences(svc.Name()))
	require.NoError(t, err)

	profileCli, err := profilev1.NewProfileClient(ctx,
		apis.WithEndpoint(cfg.ProfileServiceURI),
		apis.WithTokenEndpoint(cfg.Oauth2ServiceURI),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(cfg.Oauth2ServiceClientSecret),
		apis.WithAudiences(svc.Name()))
	require.NoError(t, err)

	srv := handlers.NewAuthServer(ctx, svc, &cfg, profileCli, partitionCli)

	authServiceHandlers := handlers2.RecoveryHandler(
		handlers2.PrintRecoveryStack(true))(
		srv.SetupRouterV1(ctx))

	defaultServer := frame.WithHTTPHandler(authServiceHandlers)
	svc.Init(ctx, defaultServer)

	err = repository.Migrate(ctx, svc, "../../migrations/0001")
	require.NoError(t, err)

	err = svc.Run(ctx, "")
	require.NoError(t, err)

	return svc, ctx
}
