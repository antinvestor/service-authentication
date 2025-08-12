package tests

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	apis "github.com/antinvestor/apis/go/common"
	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
	profilev1 "github.com/antinvestor/apis/go/profile/v1"
	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	handlers2 "github.com/gorilla/handlers"
	hydraclientgo "github.com/ory/hydra-client-go/v2"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryhydra"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

type BaseTestSuite struct {
	internaltests.BaseTestSuite

	FreeAuthPort string
}

func initResources(_ context.Context, loginUrl string) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_authentication",
		definition.WithUserName("ant"), definition.WithPassword("s3cr3t"),
		definition.WithEnableLogging(true), definition.WithUseHostMode(false))

	localHydraConfig := strings.Replace(testoryhydra.HydraConfiguration, "http://127.0.0.1:3000/", loginUrl+"/s/", 3)

	hydra := testoryhydra.NewWithOpts(
		localHydraConfig, definition.WithDependancies(pg),
		definition.WithEnableLogging(true), definition.WithUseHostMode(true))

	// Add profile and partition service dependencies
	profile := NewProfile(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))
	partition := NewPartitionSvc(definition.WithDependancies(pg, hydra), definition.WithEnableLogging(true), definition.WithUseHostMode(true))

	resources := []definition.TestResource{pg, hydra, profile, partition}
	return resources
}

func (bs *BaseTestSuite) TearDownSuite() {
	bs.BaseTestSuite.TearDownSuite()
}

func (bs *BaseTestSuite) SetupSuite() {

	bs.InitResourceFunc = func(ctx context.Context) []definition.TestResource {

		freePort, _ :=  getFreePort(ctx)
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
	cfg.RunServiceSecurely = false
	cfg.HTTPServerPort = bs.FreeAuthPort


	cfg.Oauth2ServiceClientSecret = "vkGiJroO9dAS5eFnuaGy"
	cfg.DatabasePrimaryURL = []string{testDS.String()}
	cfg.DatabaseReplicaURL = []string{testDS.String()}

	cfg.PartitionServiceURI = partitionDR.GetDS(ctx).String()
	cfg.ProfileServiceURI = profileDR.GetDS(ctx).String()
	cfg.Oauth2ServiceAdminURI = hydraDR.GetDS(ctx).String()
	cfg.Oauth2ServiceAudience = "service_profile,service_partition,service_notifications"
	cfg.Oauth2JwtVerifyAudience = "authentication_tests"
	cfg.Oauth2JwtVerifyIssuer = cfg.GetOauth2ServiceURI()

	ctx, svc := frame.NewServiceWithContext(t.Context(), "authentication_tests",
		frame.WithConfig(&cfg),
		frame.WithDatastore(),
		frame.WithNoopDriver())

	err = svc.RegisterForJwt(ctx)
	require.NoError(t, err)



	partitionCli, err := partitionv1.NewPartitionsClient(ctx,
		apis.WithEndpoint(cfg.PartitionServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithAudiences("service_partition"))
	require.NoError(t, err)

	profileCli, err := profilev1.NewProfileClient(ctx,
		apis.WithEndpoint(cfg.ProfileServiceURI),
		apis.WithTokenEndpoint(cfg.GetOauth2TokenEndpoint()),
		apis.WithTokenUsername(svc.JwtClientID()),
		apis.WithTokenPassword(svc.JwtClientSecret()),
		apis.WithAudiences("service_profile"))
	require.NoError(t, err)

	authServer := handlers.NewAuthServer(ctx, svc, &cfg, profileCli, partitionCli)

	authServiceHandlers := handlers2.RecoveryHandler(
		handlers2.PrintRecoveryStack(true))(
		authServer.SetupRouterV1(ctx))

	defaultServer := frame.WithHTTPHandler(authServiceHandlers)
	svc.Init(ctx, defaultServer)

	err = repository.Migrate(ctx, svc, "../../migrations/0001")
	require.NoError(t, err)

	go func() {
	_ = svc.Run(ctx, "")
	}()
	return authServer, ctx
}

func NewOauthClient(ctx context.Context, hydraAdminURL, serviceClientID, serviceClientSecret string, redirectUris []string) error {

	configuration := hydraclientgo.NewConfiguration()
	configuration.Servers = hydraclientgo.ServerConfigurations{{URL: hydraAdminURL}}
	apiClient := hydraclientgo.NewAPIClient(configuration).OAuth2API

	oAuth2Client := hydraclientgo.NewOAuth2Client()
	oAuth2Client.SetClientId(serviceClientID)
	oAuth2Client.SetClientSecret(serviceClientSecret)
	oAuth2Client.SetGrantTypes([]string{"client_credentials"})
	oAuth2Client.SetScope("openid profile email")
	oAuth2Client.SetTokenEndpointAuthMethod("client_secret_post")
	oAuth2Client.SetRedirectUris(redirectUris)

	_, _, clientErr := apiClient.CreateOAuth2Client(ctx).OAuth2Client(*oAuth2Client).Execute()
	if clientErr != nil && !strings.Contains(clientErr.Error(), "already exists") {
		return clientErr
	}
	return nil

}

func getFreePort(ctx context.Context) (int, error) {
	a, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	var l *net.TCPListener
	l, err = net.ListenTCP("tcp", a)
	if err != nil {
		return 0, err
	}
	defer util.CloseAndLogOnError(ctx, l)
	return l.Addr().(*net.TCPAddr).Port, nil
}
