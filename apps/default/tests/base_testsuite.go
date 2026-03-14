package tests

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"buf.build/gen/go/antinvestor/device/connectrpc/go/device/v1/devicev1connect"
	"buf.build/gen/go/antinvestor/notification/connectrpc/go/notification/v1/notificationv1connect"
	"buf.build/gen/go/antinvestor/partition/connectrpc/go/partition/v1/partitionv1connect"
	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	"connectrpc.com/connect"
	"github.com/antinvestor/apis/go/common"
	commonconnection "github.com/antinvestor/apis/go/common/connection"
	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	internaltests "github.com/antinvestor/service-authentication/pkg/tests"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/cache"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"google.golang.org/protobuf/types/known/structpb"
)

type DepsBuilder struct {
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
	cfg, _ := svc.Config().(*aconfig.AuthenticationConfig)

	depBuilder := &DepsBuilder{
		LoginRepo:      repository.NewLoginRepository(ctx, dbPool, workMan),
		LoginEventRepo: repository.NewLoginEventRepository(ctx, dbPool, workMan),
	}

	var err error

	depBuilder.PartitionCli, err = setupPartitionClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	depBuilder.NotificationCli, err = setupNotificationClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	depBuilder.ProfileCli, err = setupProfileClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	depBuilder.DeviceCli, err = setupDeviceClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return depBuilder, nil
}

type BaseTestSuite struct {
	internaltests.BaseTestSuite

	FreeAuthPort string
	handler      *handlers.AuthServer
}

type hydraServiceClientSeed struct {
	ClientID   string
	ClientName string
	Secret     string
	Audience   []string
	ProfileID  string
}

func (bs *BaseTestSuite) ServerUrl() string {
	return fmt.Sprintf("http://127.0.0.1:%s", bs.FreeAuthPort)
}

// Handler returns the main AuthServer handler created in SetupSuite.
// Use this when you need to query the same database that the HTTP handlers use.
func (bs *BaseTestSuite) Handler() *handlers.AuthServer {
	return bs.handler
}

func initResources(_ context.Context, loginUrl string, authPort int) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	// Rewrite Hydra config to point callbacks at the host-side auth server.
	// Containers reach the host via testcontainers' SSHD bridge (host.testcontainers.internal).
	dockerLoginUrl := strings.Replace(loginUrl, "127.0.0.1", testcontainers.HostInternal, 1)
	localHydraConfig := strings.Replace(internaltests.HydraConfiguration, "http://127.0.0.1:3000/", dockerLoginUrl+"/s/", 3)
	localHydraConfig = strings.Replace(localHydraConfig, "http://127.0.0.1:3000/", dockerLoginUrl+"/", 2)

	hydra := internaltests.NewHydra(
		localHydraConfig, []int{authPort}, definition.WithDependancies(pg),
		definition.WithEnableLogging(false))

	partitionSvc := internaltests.NewPartitionSvc(
		definition.WithDependancies(pg, hydra),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)
	notificationsSvc := internaltests.NewNotificationSvc(
		definition.WithDependancies(pg, hydra),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)
	profileSvc := internaltests.NewProfile(
		definition.WithDependancies(pg, hydra, notificationsSvc),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)

	deviceSvc := internaltests.NewDevice(
		definition.WithDependancies(pg, hydra),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(true),
	)

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
		return initResources(ctx, loginUrl, freePort)
	}
	bs.BaseTestSuite.SetupSuite()

	_, bs.handler, _ = bs.CreateService(bs.T(), definition.NewDependancyOption("default", "default", bs.Resources()))
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
		case internaltests.HydraImage:
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

	// Inject JWKS data before OIDC discovery so LoadWithOIDC skips the
	// remote JWKS fetch entirely and sticks to the host-mapped Hydra URL.
	jwksData, err := internaltests.FetchJWKS(ctx, hydraPort)
	require.NoError(t, err)
	t.Setenv("OAUTH2_WELL_KNOWN_JWK_DATA", jwksData)
	t.Setenv("OAUTH2_SERVICE_URI", oauth2ServiceURI.String())

	cfg, err := config.LoadWithOIDC[aconfig.AuthenticationConfig](ctx)
	require.NoError(t, err)

	hostTokenEndpoint := fmt.Sprintf("http://127.0.0.1:%s/oauth2/token", hydraPort)
	cfg.SetOIDCValue("token_endpoint", hostTokenEndpoint)

	cfg.LogLevel = "debug"
	cfg.TraceRequests = true
	cfg.DatabaseMigrate = true
	cfg.DatabaseTraceQueries = true
	// cfg.RunServiceSecurely = false
	if bs.handler == nil {
		cfg.HTTPServerPort = bs.FreeAuthPort
	}
	cfg.Oauth2ServiceClientID = "dev_authentication_tests"
	cfg.Oauth2ServiceClientSecret = "vkGiJroO9dAS5eFnuaGy"
	cfg.Oauth2TokenEndpointAuthMethod = common.TokenEndpointAuthMethodClientSecretPost
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}

	cfg.PartitionServiceURI = partitionDR.GetDS(ctx).String()
	cfg.ProfileServiceURI = profileDR.GetDS(ctx).String()
	cfg.DeviceServiceURI = deviceDR.GetDS(ctx).String()
	cfg.NotificationServiceURI = notificationDR.GetDS(ctx).String()
	cfg.Oauth2ServiceURI = oauth2ServiceURI.String()
	cfg.Oauth2ServiceAdminURI = hydraDR.GetDS(ctx).String()
	cfg.Oauth2ServiceAudience = []string{"service_profile", "service_tenancy", "service_notifications", "service_device"}
	cfg.Oauth2JwtVerifyAudience = []string{"authentication_tests"}
	cfg.Oauth2JwtVerifyIssuer = oauth2ServiceURI.String()

	err = ensureHydraServiceClients(ctx, cfg.Oauth2ServiceAdminURI)
	require.NoError(t, err)

	opts := []frame.Option{frame.WithName("authentication_tests"), frame.WithConfig(&cfg),
		frame.WithDatastore(), frame.WithCache(cfg.CacheName, cache.NewInMemoryCache())}

	if bs.handler != nil {
		opts = append(opts, frametests.WithNoopDriver())
	}

	ctx, svc := frame.NewServiceWithContext(t.Context(), opts...)

	t.Cleanup(func() {
		svc.Stop(ctx)
	})

	depsBuilder, err := BuildRepos(ctx, svc)
	require.NoError(t, err)

	authServer := handlers.NewAuthServer(ctx, svc.SecurityManager(), &cfg,
		svc.CacheManager(), depsBuilder.LoginRepo, depsBuilder.LoginEventRepo,
		depsBuilder.ProfileCli, depsBuilder.DeviceCli, depsBuilder.PartitionCli, depsBuilder.NotificationCli, nil)

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

func ensureHydraServiceClients(ctx context.Context, adminURL string) error {
	configuration := hydraclientgo.NewConfiguration()
	configuration.HTTPClient = http.DefaultClient
	configuration.Servers = []hydraclientgo.ServerConfiguration{{URL: adminURL}}

	apiClient := hydraclientgo.NewAPIClient(configuration)
	seeds := []hydraServiceClientSeed{
		{
			ClientID:   "dev_authentication_tests",
			ClientName: "sa-authentication_tests",
			Secret:     "vkGiJroO9dAS5eFnuaGy",
			Audience:   []string{"service_profile", "service_tenancy", "service_notifications", "service_device"},
			ProfileID:  "dev_authentication_tests",
		},
		{
			ClientID:   "dev_service_authentication",
			ClientName: "sa-service_authentication",
			Secret:     "vkGiJroO9dAS5eFnuaGy",
			Audience:   []string{"service_profile", "service_tenancy", "service_notifications", "service_device"},
			ProfileID:  "dev_service_authentication",
		},
		{
			ClientID:   "dev_service_profile",
			ClientName: "sa-service_profile",
			Secret:     "hkGiJroO9cDS5eFnuaAV",
			Audience:   []string{"service_notifications", "service_tenancy"},
			ProfileID:  "dev_service_profile",
		},
		{
			ClientID:   "dev_service_tenancy",
			ClientName: "sa-service_tenancy",
			Secret:     "hkGiJroO9cDS5eFnuaAV",
			Audience:   []string{"service_notifications", "service_profile", "authentication_tests"},
			ProfileID:  "dev_service_tenancy",
		},
		{
			ClientID:   "dev_service_notifications",
			ClientName: "sa-service_notifications",
			Secret:     "hkGiJroO9cDS5eFnuaAV",
			Audience:   []string{"service_profile", "service_tenancy", "service_device"},
			ProfileID:  "dev_service_notifications",
		},
		{
			ClientID:   "dev_service_devices",
			ClientName: "sa-service_devices",
			Secret:     "hkBaJroO9cDGleFnuaAZ",
			Audience:   []string{"service_notifications", "service_tenancy", "service_profile", "authentication_tests"},
			ProfileID:  "dev_service_devices",
		},
	}

	for _, seed := range seeds {
		client := hydraclientgo.NewOAuth2Client()
		client.SetClientId(seed.ClientID)
		client.SetClientName(seed.ClientName)
		client.SetClientSecret(seed.Secret)
		client.SetGrantTypes([]string{"client_credentials"})
		client.SetResponseTypes([]string{"token"})
		client.SetScope("system_int openid")
		client.SetAudience(seed.Audience)
		client.SetTokenEndpointAuthMethod(common.TokenEndpointAuthMethodClientSecretPost)
		client.SetMetadata(map[string]any{
			"tenant_id":    "9bsv0s3pbdv002o80qfg",
			"partition_id": "9bsv0s3pbdv002o80qhg",
			"profile_id":   seed.ProfileID,
			"type":         "internal",
		})

		_, _, err := apiClient.OAuth2API.
			CreateOAuth2Client(ctx).
			OAuth2Client(*client).
			Execute()
		if err == nil {
			continue
		}

		if !strings.Contains(err.Error(), "409") {
			return fmt.Errorf("create hydra service client %s: %w", seed.ClientID, err)
		}

		_, _, err = apiClient.OAuth2API.
			SetOAuth2Client(ctx, seed.ClientID).
			OAuth2Client(*client).
			Execute()
		if err != nil {
			return fmt.Errorf("ensure hydra service client %s: %w", seed.ClientID, err)
		}
	}

	return nil
}

func newTestConnectClient[T any](
	ctx context.Context,
	factory commonconnection.ConnectServiceClientFactory[T],
	opts ...common.ClientOption,
) (T, error) {
	var zero T

	httpClient, err := commonconnection.NewHTTPClient(ctx)
	if err != nil {
		return zero, err
	}

	opts = append(opts, common.WithHTTPClient(httpClient))
	return commonconnection.NewConnectClient(ctx, factory, opts...)
}

// setupDeviceClient creates and configures the device client.
func setupDeviceClient(
	ctx context.Context,
	cfg *aconfig.AuthenticationConfig) (devicev1connect.DeviceServiceClient, error) {
	opts, err := common.ClientOptions(ctx, cfg, common.ServiceTarget{
		Endpoint:  cfg.DeviceServiceURI,
		Audiences: []string{"service_device"},
	})
	if err != nil {
		return nil, err
	}

	return newTestConnectClient(ctx, devicev1connect.NewDeviceServiceClient, opts...)
}

// setupNotificationClient creates and configures the notification client.
func setupNotificationClient(
	ctx context.Context,
	cfg *aconfig.AuthenticationConfig) (notificationv1connect.NotificationServiceClient, error) {
	opts, err := common.ClientOptions(ctx, cfg, common.ServiceTarget{
		Endpoint:  cfg.NotificationServiceURI,
		Audiences: []string{"service_notifications"},
	})
	if err != nil {
		return nil, err
	}

	return newTestConnectClient(ctx, notificationv1connect.NewNotificationServiceClient, opts...)
}

// setupPartitionClient creates and configures the partition client.
func setupPartitionClient(
	ctx context.Context,
	cfg *aconfig.AuthenticationConfig) (partitionv1connect.PartitionServiceClient, error) {
	opts, err := common.ClientOptions(ctx, cfg, common.ServiceTarget{
		Endpoint:  cfg.PartitionServiceURI,
		Audiences: []string{"service_tenancy"},
	}, common.WithTraceRequests(), common.WithTraceResponses(), common.WithTraceHeaders())
	if err != nil {
		return nil, err
	}

	return newTestConnectClient(ctx, partitionv1connect.NewPartitionServiceClient, opts...)
}

// setupProfileClient creates and configures the profile client.
func setupProfileClient(
	ctx context.Context,
	cfg *aconfig.AuthenticationConfig) (profilev1connect.ProfileServiceClient, error) {
	opts, err := common.ClientOptions(ctx, cfg, common.ServiceTarget{
		Endpoint:  cfg.ProfileServiceURI,
		Audiences: []string{"service_profile"},
	})
	if err != nil {
		return nil, err
	}

	return newTestConnectClient(ctx, profilev1connect.NewProfileServiceClient, opts...)
}

func NewPartitionForOauthCli(ctx context.Context, partitionCli partitionv1connect.PartitionServiceClient, name, description string, properties data.JSONMap) (*partitionv1.PartitionObject, error) {

	var propsStruct *structpb.Struct
	if properties != nil {
		propsStruct = properties.ToProtoStruct()
	}

	result, err := partitionCli.CreatePartition(ctx, connect.NewRequest(&partitionv1.CreatePartitionRequest{
		TenantId:    "c2f4j7au6s7f91uqnojg",
		ParentId:    "c2f4j7au6s7f91uqnokg",
		Name:        name,
		Description: description,
		Properties:  propsStruct,
	}))
	if err != nil {
		util.Log(ctx).WithError(err).Error("failed to create partition")
		return nil, err
	}

	return result.Msg.GetData(), nil
}
