package tests

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	apis "github.com/antinvestor/apis/go/common"
	devicev1 "github.com/antinvestor/apis/go/device/v1"
	notificationv1 "github.com/antinvestor/apis/go/notification/v1"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/stretchr/testify/require"
)

type BaseTestSuite struct {
	internaltests.BaseTestSuite

	FreeAuthPort string
}

func (bs *BaseTestSuite) ServerUrl() string {
	return fmt.Sprintf("http://127.0.0.1:%s", bs.FreeAuthPort)
}

func initResources(_ context.Context, loginUrl string) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithPassword("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	localHydraConfig := strings.Replace(testoryhydra.HydraConfiguration, "http://127.0.0.1:3000/", loginUrl+"/s/", 3)

	hydra := testoryhydra.NewWithOpts(
		localHydraConfig, definition.WithDependancies(pg),
		definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	// Add profile and partition service dependencies
	device := internaltests.NewDevice(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(false), definition.WithUseHostMode(true))
	partition := internaltests.NewPartitionSvc(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(false), definition.WithUseHostMode(true))
	notifications := internaltests.NewNotificationSvc(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(false), definition.WithUseHostMode(true))
	profile := internaltests.NewProfile(definition.WithDependancies(pg, hydra, notifications), definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	resources := []definition.TestResource{pg, hydra, notifications, profile, device, partition}
	return resources
}

func (bs *BaseTestSuite) TearDownSuite() {
	bs.BaseTestSuite.TearDownSuite()
}

func (bs *BaseTestSuite) SetupSuite() {

	bs.InitResourceFunc = func(ctx context.Context) []definition.TestResource {

		freePort, _ := frametests.GetFreePort(ctx)
		bs.FreeAuthPort = strconv.Itoa(freePort)

		loginUrl := fmt.Sprintf("http://127.0.0.1:%s", bs.FreeAuthPort)
		return initResources(ctx, loginUrl)
	}
	bs.BaseTestSuite.SetupSuite()
}

func (bs *BaseTestSuite) CreateService(
	t *testing.T,
	depOpts *definition.DependancyOption,
) (*handlers.AuthServer, context.Context) {
	t.Setenv("OTEL_TRACES_EXPORTER", "none")

	var databaseDR definition.DependancyConn
	var hydraDR definition.DependancyConn
	var profileDR definition.DependancyConn
	var deviceDR definition.DependancyConn
	var partitionDR definition.DependancyConn
	var notificationDR definition.DependancyConn
	for _, res := range bs.Resources() {
		switch res.Name() {
		case testpostgres.PostgresqlDBImage:
			databaseDR = res
		case internaltests.ProfileImage:
			profileDR = res
		case internaltests.DeviceImage:
			deviceDR = res
		case internaltests.PartitionImage:
			partitionDR = res
		case internaltests.NotificationImage:
			notificationDR = res
		case testoryhydra.OryHydraImage:
			hydraDR = res
		}
	}

	ctx := t.Context()
	testDS, cleanup, err0 := databaseDR.GetRandomisedDS(ctx, depOpts.Prefix())
	require.NoError(t, err0)
	t.Cleanup(func() {
		cleanup(ctx)
	})

	t.Setenv("OTEL_TRACES_EXPORTER", "none")

	hydraPort, err := hydraDR.PortMapping(ctx, "4444/tcp")
	require.NoError(t, err)

	oauth2ServiceURI, err := hydraDR.GetDS(ctx).ChangePort(hydraPort)
	require.NoError(t, err)

	t.Setenv("OAUTH2_SERVICE_URI", oauth2ServiceURI.String())

	cfg, err := frame.ConfigLoadWithOIDC[config.AuthenticationConfig](ctx)
	require.NoError(t, err)

	cfg.LogLevel = "debug"
	cfg.DatabaseTraceQueries = true
	// cfg.RunServiceSecurely = false
	cfg.HTTPServerPort = bs.FreeAuthPort

	cfg.Oauth2ServiceClientSecret = "vkGiJroO9dAS5eFnuaGy"
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}

	cfg.PartitionServiceURI = partitionDR.GetDS(ctx).String()
	cfg.ProfileServiceURI = profileDR.GetDS(ctx).String()
	cfg.DeviceServiceURI = deviceDR.GetDS(ctx).String()
	cfg.Oauth2ServiceAdminURI = hydraDR.GetDS(ctx).String()
	cfg.Oauth2ServiceAudience = "service_profile,service_partition,service_notifications,service_devices"
	cfg.Oauth2JwtVerifyAudience = "authentication_tests"
	cfg.Oauth2JwtVerifyIssuer = cfg.GetOauth2ServiceURI()

	ctx, svc := frame.NewServiceWithContext(t.Context(), "authentication_tests",
		frame.WithConfig(&cfg),
		frame.WithDatastore(),
		frametests.WithNoopDriver())

	err = svc.RegisterForJwt(ctx)
	require.NoError(t, err)

	partitionCli, err := partitionv1.NewPartitionsClient(ctx,
		apis.WithEndpoint(cfg.PartitionServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstSystemScopeInternal),
		apis.WithAudiences("service_partition"))
	require.NoError(t, err)

	profileCli, err := profilev1.NewProfileClient(ctx,
		apis.WithEndpoint(cfg.ProfileServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstSystemScopeInternal),
		apis.WithAudiences("service_profile"))
	require.NoError(t, err)

	deviceCli, err := devicev1.NewDeviceClient(ctx,
		apis.WithEndpoint(cfg.DeviceServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstSystemScopeInternal),
		apis.WithAudiences("service_devices"))
	require.NoError(t, err)

	notificationCli, err := notificationv1.NewNotificationClient(ctx,
		apis.WithEndpoint(notificationDR.GetDS(ctx).String()),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithScopes(frame.ConstSystemScopeInternal),
		apis.WithAudiences("service_notifications"))
	require.NoError(t, err)

	authServer := handlers.NewAuthServer(ctx, svc, &cfg, profileCli, deviceCli, partitionCli, notificationCli)

	authServiceHandlers := authServer.SetupRouterV1(ctx)

	defaultServer := frame.WithHTTPHandler(authServiceHandlers)
	svc.Init(ctx, defaultServer)

	err = repository.Migrate(ctx, svc, "../../migrations/0001")
	require.NoError(t, err)

	go func() {
		_ = svc.Run(ctx, "")
	}()
	return authServer, ctx
}

func NewPartitionForOauthCli(ctx context.Context, partitionCli *partitionv1.PartitionClient, name, description string, properties frame.JSONMap) (*partitionv1.PartitionObject, error) {

	result, err := partitionCli.Svc().CreatePartition(ctx, &partitionv1.CreatePartitionRequest{
		TenantId:    "c2f4j7au6s7f91uqnojg",
		ParentId:    "c2f4j7au6s7f91uqnokg",
		Name:        name,
		Description: description,
		Properties:  properties.ToProtoStruct(),
	})
	if err != nil {
		return nil, err
	}

	partition := result.GetData()

	// wait for partition to be synced
	partition, err = frametests.WaitForConditionWithResult(ctx, func() (*partitionv1.PartitionObject, error) {

		partition, err = partitionCli.GetPartition(ctx, partition.GetId())
		if err != nil {
			return nil, nil
		}

		var partProperties frame.JSONMap = partition.GetProperties().AsMap()
		_, ok := partProperties["client_id"]
		if ok {
			return partition, nil
		}

		return nil, nil

	}, 2*time.Second, 200*time.Millisecond)

	if err != nil {
		return nil, fmt.Errorf("failed to synchronise partition in time: %w", err)
	}

	return partition, nil
}
