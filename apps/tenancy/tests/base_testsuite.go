package tests

import (
	"context"
	"fmt"
	"testing"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testnats"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type BaseTestSuite struct {
	internaltests.BaseTestSuite
}

func initResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_tenancy",
		definition.WithUserName("ant"), definition.WithPassword("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	queue := testnats.NewWithOpts("partition",
		definition.WithUserName("ant"),
		definition.WithPassword("s3cr3t"),
		definition.WithEnableLogging(false))

	hydra := testoryhydra.NewWithOpts(
		testoryhydra.HydraConfiguration, definition.WithDependancies(pg),
		definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	auth := internaltests.NewAuthentication(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	resources := []definition.TestResource{pg, queue, hydra, auth}
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
	_, svc, ctx := bs.CreateServiceWithPortAccess(t, depOpts, 0)
	return svc, ctx
}

func (bs *BaseTestSuite) CreateServiceWithPortAccess(
	t *testing.T, depOpts *definition.DependancyOption, accessPort int) (
	*handlers.PartitionServer, *frame.Service, context.Context) {

	ctx := t.Context()

	var databaseDR definition.DependancyConn
	var queueDR definition.DependancyConn
	var hydraDR definition.DependancyConn
	// var authenticationDR definition.DependancyConn
	for _, res := range bs.Resources() {
		switch res.Name() {
		case testpostgres.PostgresqlDBImage:
			databaseDR = res
		case testnats.NatsImage:
			queueDR = res
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

	qDS, err := queueDR.GetDS(ctx).WithUser("ant")
	require.NoError(t, err)

	qDS, err = qDS.WithPassword("s3cr3t")
	require.NoError(t, err)

	cfg.LogLevel = "debug"
	cfg.HTTPServerPort = fmt.Sprintf(":%d", accessPort)
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}
	cfg.Oauth2ServiceAdminURI = hydraDR.GetDS(ctx).String()
	cfg.EventsQueueURL = qDS.
		ExtendQuery("jetstream", "true").
		ExtendQuery("subject", "svc.tenancy.internal._queue_"+depOpts.Prefix()).
		ExtendQuery("stream_name", "svc_tenancy").
		ExtendQuery("stream_subjects", "svc.tenancy.>").
		ExtendQuery("consumer_durable_name", "svc_tenancy_internal_queue_"+depOpts.Prefix()).
		ExtendQuery("consumer_filter_subject", "svc.tenancy.internal._queue_"+depOpts.Prefix()).
		ExtendQuery("consumer_ack_policy", "explicit").
		ExtendQuery("consumer_deliver_policy", "all").
		ExtendQuery("consumer_replay_policy", "instant").
		ExtendQuery("stream_retention", "workqueue").
		ExtendQuery("stream_storage", "file").
		String()

	ctx, svc := frame.NewServiceWithContext(ctx, "tenancy tests",
		frame.WithConfig(&cfg), frame.WithDatastore(), frametests.WithNoopDriver())

	serviceOptions := []frame.Option{frame.WithRegisterEvents(
		events.NewPartitionSynchronizationEventHandler(svc),
	)}

	implementation := handlers.NewPartitionServer(ctx, svc)
	grpcServer := grpc.NewServer()
	partitionv1.RegisterPartitionServiceServer(grpcServer, implementation)

	serviceOptions = append(serviceOptions, frame.WithHTTPHandler(implementation.NewSecureRouterV1()))

	svc.Init(ctx, serviceOptions...)

	err = repository.Migrate(ctx, svc, "../../migrations/0001")
	require.NoError(t, err)

	_ = svc.Run(ctx, "")

	return implementation, svc, ctx
}
