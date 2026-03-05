package tests

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/tenancy/config"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/handlers"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests/testketo"
	internaltests "github.com/antinvestor/service-authentication/internal/tests"
	"github.com/pitabwire/frame"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testnats"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

type DepsBuilder struct {
	TenantRepo        repository.TenantRepository
	PartitionRepo     repository.PartitionRepository
	PartitionRoleRepo repository.PartitionRoleRepository
	AccessRepo        repository.AccessRepository
	AccessRoleRepo    repository.AccessRoleRepository
	PageRepo          repository.PageRepository

	PartitionBusiness business.PartitionBusiness
	TenantBusiness    business.TenantBusiness
	AccessBusiness    business.AccessBusiness
	PageBusiness      business.PageBusiness

	Server *handlers.PartitionServer
}

func BuildDeps(ctx context.Context, svc *frame.Service, server *handlers.PartitionServer) *DepsBuilder {
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := svc.WorkManager()
	cfg := svc.Config().(*aconfig.PartitionConfig)
	eventsMan := svc.EventsManager()

	depBuilder := &DepsBuilder{
		TenantRepo:        repository.NewTenantRepository(ctx, dbPool, workMan),
		PartitionRepo:     repository.NewPartitionRepository(ctx, dbPool, workMan),
		PartitionRoleRepo: repository.NewPartitionRoleRepository(ctx, dbPool, workMan),
		AccessRepo:        repository.NewAccessRepository(ctx, dbPool, workMan),
		AccessRoleRepo:    repository.NewAccessRoleRepository(ctx, dbPool, workMan),
		PageRepo:          repository.NewPageRepository(ctx, dbPool, workMan),
		Server:            server,
	}

	depBuilder.PartitionBusiness = business.NewPartitionBusiness(*cfg, eventsMan, depBuilder.TenantRepo, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo)
	depBuilder.TenantBusiness = business.NewTenantBusiness(svc, depBuilder.TenantRepo)
	depBuilder.AccessBusiness = business.NewAccessBusiness(svc, eventsMan, depBuilder.AccessRepo, depBuilder.AccessRoleRepo, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo)
	depBuilder.PageBusiness = business.NewPageBusiness(svc, depBuilder.PageRepo, depBuilder.PartitionRepo)

	return depBuilder
}

type BaseTestSuite struct {
	internaltests.BaseTestSuite

	ketoReadURI  string
	ketoWriteURI string
}

func initResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.NewWithOpts("service_tenancy",
		definition.WithUserName("ant"), definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false), definition.WithUseHostMode(false))

	queue := testnats.NewWithOpts("partition",
		definition.WithUserName("ant"),
		definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false))

	hydra := internaltests.NewHydra(
		internaltests.HydraConfiguration, nil, definition.WithDependancies(pg),
		definition.WithEnableLogging(false))

	keto := testketo.NewWithOpts(
		definition.WithDependancies(pg),
		definition.WithEnableLogging(false),
	)

	resources := []definition.TestResource{pg, queue, hydra, keto}
	return resources
}

func (bs *BaseTestSuite) SetupSuite() {

	bs.InitResourceFunc = initResources
	bs.BaseTestSuite.SetupSuite()

	ctx := bs.T().Context()

	var ketoDep definition.DependancyConn
	for _, res := range bs.Resources() {
		if res.Name() == testketo.ImageName {
			ketoDep = res
			break
		}
	}
	bs.Require().NotNil(ketoDep, "keto dependency should be available")

	writeURL, err := url.Parse(string(ketoDep.GetDS(ctx)))
	bs.Require().NoError(err)
	bs.ketoWriteURI = writeURL.Host

	readPort, err := ketoDep.PortMapping(ctx, "4466/tcp")
	bs.Require().NoError(err)
	bs.ketoReadURI = fmt.Sprintf("%s:%s", writeURL.Hostname(), readPort)
}

func (bs *BaseTestSuite) CreateService(
	t *testing.T,
	depOpts *definition.DependencyOption,
) (context.Context, *frame.Service, *DepsBuilder) {

	ctx := t.Context()

	var databaseDR definition.DependancyConn
	var queueDR definition.DependancyConn
	var hydraDR definition.DependancyConn
	for _, res := range bs.Resources() {
		switch res.Name() {
		case testpostgres.PostgresqlDBImage:
			databaseDR = res
		case testnats.NatsImage:
			queueDR = res
		case internaltests.HydraImage:
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

	cfg, err := config.LoadWithOIDC[aconfig.PartitionConfig](ctx)
	require.NoError(t, err)

	// Hydra's public URL is the internal Docker address; rewrite token endpoint for host.
	hostTokenEndpoint := fmt.Sprintf("http://127.0.0.1:%s/oauth2/token", hydraPort)
	cfg.SetOIDCValue("token_endpoint", hostTokenEndpoint)

	qDS, err := queueDR.GetDS(ctx).WithUser("ant")
	require.NoError(t, err)

	qDS, err = qDS.WithPassword("s3cr3t")
	require.NoError(t, err)

	cfg.LogLevel = "debug"

	cfg.DatabaseMigrate = true
	cfg.DatabaseTraceQueries = true

	testDSLimited := testDS.
		ExtendQuery("pool_max_conns", "2").
		ExtendQuery("pool_max_conn_idle_time", "200ms").
		ExtendQuery("pool_health_check_period", "200ms")
	cfg.DatabasePrimaryURL = []string{testDSLimited.String()}
	cfg.DatabaseReplicaURL = []string{}
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
	cfg.SynchronizePrimaryPartitions = true

	cfg.AuthorizationServiceReadURI = bs.ketoReadURI
	cfg.AuthorizationServiceWriteURI = bs.ketoWriteURI

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithName("tenancy tests"),
		frame.WithConfig(&cfg), frame.WithDatastore(), frametests.WithNoopDriver())

	auth := svc.SecurityManager().GetAuthorizer(ctx)
	authzMiddleware := authz.NewMiddleware(auth)
	implementation := handlers.NewPartitionServer(ctx, svc, authzMiddleware, auth)

	serviceOptions := []frame.Option{frame.WithRegisterEvents(
		events.NewPartitionSynchronizationEventHandler(ctx, &cfg, svc.HTTPClientManager(), implementation.PartitionRepo),
		events.NewClientSynchronizationEventHandler(ctx, &cfg, svc.HTTPClientManager(), implementation.ClientRepo, implementation.ServiceAccountRepo),
		events.NewServiceAccountSynchronizationEventHandler(ctx, &cfg, svc.HTTPClientManager(), implementation.ServiceAccountRepo, implementation.PartitionRepo),
		events.NewAuthzPartitionSyncEventHandler(implementation.PartitionRepo, auth),
		events.NewAuthzServiceAccountSyncEventHandler(implementation.ServiceAccountRepo, auth),
		events.NewTupleWriteEventHandler(auth),
		events.NewTupleDeleteEventHandler(auth),
	)}

	serviceOptions = append(serviceOptions, frame.WithHTTPHandler(implementation.NewSecureRouterV1()))

	svc.Init(ctx, serviceOptions...)

	err = repository.Migrate(ctx, svc.DatastoreManager(), "../../migrations/0001")
	require.NoError(t, err)

	_ = svc.Run(ctx, "")

	t.Cleanup(func() {
		bgCtx := context.Background()
		svc.Stop(bgCtx)
		// Allow leaked pgxpool health checks to close idle connections
		// before the next test tries to open new ones.
		time.Sleep(500 * time.Millisecond)
	})

	deps := BuildDeps(ctx, svc, implementation)

	return ctx, svc, deps
}

func (bs *BaseTestSuite) WithAuthClaims(ctx context.Context, tenantID, partitionID, profileID string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID:    tenantID,
		PartitionID: partitionID,
		AccessID:    util.IDString(),
		ContactID:   profileID,
		SessionID:   util.IDString(),
		DeviceID:    "test-device",
	}
	claims.Subject = profileID
	return claims.ClaimsToContext(ctx)
}

// SeedTenantAccess writes a tenancy_access member tuple so the profile can pass
// the TenancyAccessChecker (data access layer).
func (bs *BaseTestSuite) SeedTenantAccess(ctx context.Context, svc *frame.Service, tenantID, partitionID, profileID string) {
	auth := svc.SecurityManager().GetAuthorizer(ctx)
	tenancyPath := fmt.Sprintf("%s/%s", tenantID, partitionID)
	err := auth.WriteTuple(ctx, authz.BuildAccessTuple(tenancyPath, profileID))
	bs.Require().NoError(err, "failed to seed tenant access")
}

// SeedTenantRole writes a role tuple in the service_tenancy namespace.
// Only the role tuple is needed — Keto evaluates OPL permits for permission resolution.
func (bs *BaseTestSuite) SeedTenantRole(ctx context.Context, svc *frame.Service, tenantID, partitionID, profileID, role string) {
	auth := svc.SecurityManager().GetAuthorizer(ctx)
	tenancyPath := fmt.Sprintf("%s/%s", tenantID, partitionID)

	tuples := authz.BuildRoleTuples(tenancyPath, profileID, role)
	err := auth.WriteTuples(ctx, tuples)
	bs.Require().NoError(err, "failed to seed tenant role")
}
