package tests

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"buf.build/gen/go/antinvestor/device/connectrpc/go/device/v1/devicev1connect"
	"buf.build/gen/go/antinvestor/notification/connectrpc/go/notification/v1/notificationv1connect"
	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"connectrpc.com/connect"
	"github.com/antinvestor/apis/go/common"
	"github.com/antinvestor/apis/go/device"
	"github.com/antinvestor/apis/go/notification"
	"github.com/antinvestor/apis/go/partition"
	"github.com/antinvestor/apis/go/profile"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/openid"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

type DepsBuilder struct {
	APIKeyRepo     repository.APIKeyRepository
	LoginRepo      repository.LoginRepository
	LoginEventRepo repository.LoginEventRepository

	ProfileCli      profilev1connect.ProfileServiceClient
	DeviceCli       devicev1connect.DeviceServiceClient
	PartitionCli    partitionv1connect.PartitionServiceClient
	NotificationCli notificationv1connect.NotificationServiceClient
}

func BuildRepos(ctx context.Context, svc *frame.Service) (*DepsBuilder, error) {
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := svc.WorkManager()
	sMan := svc.SecurityManager()
	// qMan := svc.QueueManager()
	//
	cfg, _ := svc.Config().(*aconfig.AuthenticationConfig)

	depBuilder := &DepsBuilder{
		APIKeyRepo:     repository.NewAPIKeyRepository(ctx, dbPool, workMan),
		LoginRepo:      repository.NewLoginRepository(ctx, dbPool, workMan),
		LoginEventRepo: repository.NewLoginEventRepository(ctx, dbPool, workMan),
	}

	var err error

	depBuilder.PartitionCli, err = setupPartitionClient(ctx, sMan, cfg)
	if err != nil {
		return nil, err
	}
	depBuilder.NotificationCli, err = setupNotificationClient(ctx, sMan, cfg)
	if err != nil {
		return nil, err
	}

	depBuilder.ProfileCli, err = setupProfileClient(ctx, sMan, cfg)
	if err != nil {
		return nil, err
	}

	depBuilder.DeviceCli, err = setupDeviceClient(ctx, sMan, cfg)
	if err != nil {
		return nil, err
	}

	return depBuilder, nil
}

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
	localHydraConfig = strings.Replace(localHydraConfig, "http://127.0.0.1:3000/", loginUrl+"/", 2)

	hydra := testoryhydra.NewWithOpts(
		localHydraConfig, definition.WithDependancies(pg),
		definition.WithEnableLogging(false), definition.WithUseHostMode(true))

	// Add profileSvc and partitionSvc service dependencies
	deviceSvc := internaltests.NewDevice(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))
	partitionSvc := internaltests.NewPartitionSvc(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))
	notificationsSvc := internaltests.NewNotificationSvc(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))
	profileSvc := internaltests.NewProfile(definition.WithDependancies(pg, hydra, notificationsSvc), definition.WithEnableLogging(true), definition.WithUseHostMode(true))

	resources := []definition.TestResource{pg, hydra, partitionSvc, notificationsSvc, profileSvc, deviceSvc}
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
	depOpts *definition.DependencyOption,
) (context.Context, *handlers.AuthServer, *DepsBuilder) {

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

	hydraPort, err := hydraDR.PortMapping(ctx, "4444/tcp")
	require.NoError(t, err)

	oauth2ServiceURI, err := hydraDR.GetDS(ctx).ChangePort(hydraPort)
	require.NoError(t, err)

	t.Setenv("OAUTH2_SERVICE_URI", oauth2ServiceURI.String())

	cfg, err := config.LoadWithOIDC[aconfig.AuthenticationConfig](ctx)
	require.NoError(t, err)

	cfg.LogLevel = "debug"
	cfg.TraceRequests = true
	cfg.DatabaseMigrate = true
	cfg.DatabaseTraceQueries = true
	// cfg.RunServiceSecurely = false
	cfg.HTTPServerPort = bs.FreeAuthPort

	cfg.Oauth2ServiceClientSecret = "vkGiJroO9dAS5eFnuaGy"
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}

	cfg.PartitionServiceURI = partitionDR.GetDS(ctx).String()
	cfg.ProfileServiceURI = profileDR.GetDS(ctx).String()
	cfg.DeviceServiceURI = deviceDR.GetDS(ctx).String()
	cfg.NotificationServiceURI = notificationDR.GetDS(ctx).String()
	cfg.Oauth2ServiceURI = oauth2ServiceURI.String()
	cfg.Oauth2ServiceAdminURI = hydraDR.GetDS(ctx).String()
	cfg.Oauth2ServiceAudience = []string{"service_profile", "service_partition", "service_notifications", "service_devices"}
	cfg.Oauth2JwtVerifyAudience = []string{"authentication_tests"}
	cfg.Oauth2JwtVerifyIssuer = cfg.GetOauth2ServiceURI()

	ctx, svc := frame.NewServiceWithContext(t.Context(),
		frame.WithName("authentication_tests"), frame.WithConfig(&cfg),
		frame.WithDatastore(), frame.WithRegisterServerOauth2Client())

	t.Cleanup(func() {
		svc.Stop(ctx)
	})

	depsBuilder, err := BuildRepos(ctx, svc)
	require.NoError(t, err)

	authServer := handlers.NewAuthServer(ctx, svc, &cfg,
		depsBuilder.LoginRepo, depsBuilder.LoginEventRepo, depsBuilder.APIKeyRepo,
		depsBuilder.ProfileCli, depsBuilder.DeviceCli, depsBuilder.PartitionCli, depsBuilder.NotificationCli)

	authServiceHandlers := authServer.SetupRouterV1(ctx)

	defaultServer := frame.WithHTTPHandler(authServiceHandlers)
	svc.Init(ctx, defaultServer)

	err = repository.Migrate(ctx, svc.DatastoreManager(), "../../migrations/0001")
	require.NoError(t, err)

	go func() {
		_ = svc.Run(ctx, "")
	}()
	return security.SkipTenancyChecksOnClaims(ctx), authServer, depsBuilder
}

// setupDeviceClient creates and configures the device client.
func setupDeviceClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg *aconfig.AuthenticationConfig) (devicev1connect.DeviceServiceClient, error) {
	return device.NewClient(ctx,
		common.WithEndpoint(cfg.DeviceServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_devices"))
}

// setupNotificationClient creates and configures the notification client.
func setupNotificationClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg *aconfig.AuthenticationConfig) (notificationv1connect.NotificationServiceClient, error) {
	return notification.NewClient(ctx,
		common.WithEndpoint(cfg.NotificationServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_notifications"))
}

// setupPartitionClient creates and configures the partition client.
func setupPartitionClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg *aconfig.AuthenticationConfig) (partitionv1connect.PartitionServiceClient, error) {
	return partition.NewClient(ctx,
		common.WithEndpoint(cfg.PartitionServiceURI),
		common.WithTraceRequests(),
		common.WithTraceResponses(),
		common.WithTraceHeaders(),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_partition"))
}

// setupProfileClient creates and configures the profile client.
func setupProfileClient(
	ctx context.Context,
	clHolder security.InternalOauth2ClientHolder,
	cfg *aconfig.AuthenticationConfig) (profilev1connect.ProfileServiceClient, error) {
	return profile.NewClient(ctx,
		common.WithEndpoint(cfg.ProfileServiceURI),
		common.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		common.WithTokenUsername(clHolder.JwtClientID()),
		common.WithTokenPassword(clHolder.JwtClientSecret()),
		common.WithScopes(openid.ConstSystemScopeInternal),
		common.WithAudiences("service_profile"))
}

func NewPartitionForOauthCli(ctx context.Context, partitionCli partitionv1connect.PartitionServiceClient, name, description string, properties data.JSONMap) (*partitionv1.PartitionObject, error) {

	result, err := partitionCli.CreatePartition(ctx, connect.NewRequest(&partitionv1.CreatePartitionRequest{
		TenantId:    "c2f4j7au6s7f91uqnojg",
		ParentId:    "c2f4j7au6s7f91uqnokg",
		Name:        name,
		Description: description,
		Properties:  properties.ToProtoStruct(),
	}))
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to create partition")
		return nil, err
	}

	res := result.Msg.GetData()

	// wait for partition to be synced
	res, err = frametests.WaitForConditionWithResult(ctx, func() (*partitionv1.PartitionObject, error) {

		response, err0 := partitionCli.GetPartition(ctx, connect.NewRequest(&partitionv1.GetPartitionRequest{
			Id: res.GetId(),
		}))
		if err0 != nil {
			return nil, nil
		}

		prt := response.Msg.GetData()

		var partProperties data.JSONMap = prt.GetProperties().AsMap()
		_, ok := partProperties["client_id"]
		if ok {
			return prt, nil
		}

		return nil, nil

	}, 2*time.Second, 200*time.Millisecond)

	if err != nil {
		return nil, fmt.Errorf("failed to synchronise partition in time: %w", err)
	}

	return res, nil
}
