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
	"github.com/pitabwire/frame/client"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/data"
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
	TenantRepo         repository.TenantRepository
	PartitionRepo      repository.PartitionRepository
	PartitionRoleRepo  repository.PartitionRoleRepository
	AccessRepo         repository.AccessRepository
	AccessRoleRepo     repository.AccessRoleRepository
	PageRepo           repository.PageRepository
	ClientRepo         repository.ClientRepository
	ServiceAccountRepo repository.ServiceAccountRepository

	PartitionBusiness      business.PartitionBusiness
	TenantBusiness         business.TenantBusiness
	AccessBusiness         business.AccessBusiness
	PageBusiness           business.PageBusiness
	ClientBusiness         business.ClientBusiness
	ServiceAccountBusiness business.ServiceAccountBusiness

	Server *handlers.PartitionServer
}

func BuildDeps(ctx context.Context, svc *frame.Service, server *handlers.PartitionServer) *DepsBuilder {
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := svc.WorkManager()
	cfg := svc.Config().(*aconfig.PartitionConfig)
	eventsMan := svc.EventsManager()

	clientRepo := repository.NewClientRepository(ctx, dbPool, workMan)
	serviceAccountRepo := repository.NewServiceAccountRepository(ctx, dbPool, workMan)

	depBuilder := &DepsBuilder{
		TenantRepo:         repository.NewTenantRepository(ctx, dbPool, workMan),
		PartitionRepo:      repository.NewPartitionRepository(ctx, dbPool, workMan),
		PartitionRoleRepo:  repository.NewPartitionRoleRepository(ctx, dbPool, workMan),
		AccessRepo:         repository.NewAccessRepository(ctx, dbPool, workMan),
		AccessRoleRepo:     repository.NewAccessRoleRepository(ctx, dbPool, workMan),
		PageRepo:           repository.NewPageRepository(ctx, dbPool, workMan),
		ClientRepo:         clientRepo,
		ServiceAccountRepo: serviceAccountRepo,
		Server:             server,
	}

	auth := svc.SecurityManager().GetAuthorizer(ctx)
	depBuilder.PartitionBusiness = business.NewPartitionBusiness(*cfg, eventsMan, depBuilder.TenantRepo, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo, depBuilder.AccessRepo, clientRepo, serviceAccountRepo)
	depBuilder.TenantBusiness = business.NewTenantBusiness(svc, depBuilder.TenantRepo, depBuilder.PartitionRepo)
	depBuilder.AccessBusiness = business.NewAccessBusiness(svc, eventsMan, depBuilder.AccessRepo, depBuilder.AccessRoleRepo, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo, clientRepo)
	depBuilder.PageBusiness = business.NewPageBusiness(svc, depBuilder.PageRepo, depBuilder.PartitionRepo)
	depBuilder.ClientBusiness = business.NewClientBusiness(eventsMan, depBuilder.PartitionRepo, clientRepo)
	depBuilder.ServiceAccountBusiness = business.NewServiceAccountBusiness(
		eventsMan, auth, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo,
		clientRepo, serviceAccountRepo, depBuilder.AccessRepo, depBuilder.AccessRoleRepo,
	)

	return depBuilder
}

type BaseTestSuite struct {
	internaltests.BaseTestSuite

	ketoReadURI  string
	ketoWriteURI string

	// Suite-level service (set by CreateSuiteService, used to share one service across all tests).
	SuiteCtx  context.Context
	SuiteSvc  *frame.Service
	SuiteDeps *DepsBuilder
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

// CreateSuiteService creates a single service for the entire test suite.
// Call this from SetupSuite in your concrete suite type.
// The service is cleaned up in TearDownSuite.
func (bs *BaseTestSuite) CreateSuiteService() {
	t := bs.T()
	prefix := util.RandomAlphaNumericString(8)
	depOpts := definition.NewDependancyOption("default", prefix, bs.Resources())
	bs.SuiteCtx, bs.SuiteSvc, bs.SuiteDeps = bs.createServiceInternal(t, depOpts)
}

func (bs *BaseTestSuite) TearDownSuite() {
	if bs.SuiteSvc != nil {
		bgCtx := context.Background()
		bs.SuiteSvc.Stop(bgCtx)
	}
	bs.BaseTestSuite.TearDownSuite()
}

func (bs *BaseTestSuite) CreateService(
	t *testing.T,
	depOpts *definition.DependencyOption,
) (context.Context, *frame.Service, *DepsBuilder) {
	ctx, svc, deps := bs.createServiceInternal(t, depOpts)

	t.Cleanup(func() {
		bgCtx := context.Background()
		svc.Stop(bgCtx)
		time.Sleep(500 * time.Millisecond)
	})

	return ctx, svc, deps
}

func (bs *BaseTestSuite) createServiceInternal(
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

	// Inject JWKS data before OIDC discovery so LoadWithOIDC skips
	// the remote JWKS fetch (which would hit unreachable http://hydra:4444).
	jwksData, err := internaltests.FetchJWKS(ctx, hydraPort)
	require.NoError(t, err)
	t.Setenv("OAUTH2_WELL_KNOWN_JWK_DATA", jwksData)
	t.Setenv("OAUTH2_SERVICE_URI", oauth2ServiceURI.String())

	cfg, err := config.LoadWithOIDC[aconfig.PartitionConfig](ctx)
	require.NoError(t, err)

	// Hydra's issuer and public URLs both use http://hydra:4444 so OIDC
	// discovery returns container-reachable endpoints.  Override the
	// token endpoint on the host side to the mapped port.
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
	cfg.SynchronizeClients = true

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

	// Sync seeded clients to Hydra so SA credentials work for service-to-service auth
	syncSeededClientsToHydra(ctx, &cfg, svc.HTTPClientManager(), implementation)

	deps := BuildDeps(ctx, svc, implementation)

	return ctx, svc, deps
}

func (bs *BaseTestSuite) WithAuthClaims(ctx context.Context, tenantID, partitionID, profileID string) context.Context {
	return bs.WithAuthClaimsAndRoles(ctx, tenantID, partitionID, profileID, nil)
}

func (bs *BaseTestSuite) WithAuthClaimsAndRoles(ctx context.Context, tenantID, partitionID, profileID string, roles []string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID:    tenantID,
		PartitionID: partitionID,
		AccessID:    util.IDString(),
		ContactID:   profileID,
		SessionID:   util.IDString(),
		DeviceID:    "test-device",
		Roles:       roles,
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

// syncSeededClientsToHydra syncs all unsynced Client records to Hydra after
// migrations so that seeded SA credentials work for service-to-service auth.
func syncSeededClientsToHydra(ctx context.Context, cfg *aconfig.PartitionConfig, cliMan client.Manager, partSrv *handlers.PartitionServer) {
	log := util.Log(ctx)
	syncCtx := security.SkipTenancyChecksOnClaims(ctx)

	query := data.NewSearchQuery(
		data.WithSearchLimit(200),
		data.WithSearchFiltersAndByValue(map[string]any{"synced_at IS NULL": ""}),
	)

	jobResult, err := partSrv.ClientRepo.Search(syncCtx, query)
	if err != nil {
		log.WithError(err).Error("failed to search unsynced clients for Hydra sync")
		return
	}

	synced := 0
	for {
		result, ok := jobResult.ReadResult(syncCtx)
		if !ok {
			break
		}
		if result.IsError() {
			log.WithError(result.Error()).Error("error reading unsynced clients")
			break
		}
		for _, cl := range result.Item() {
			profileID := ""
			if cl.Type == "internal" || cl.Type == "external" {
				sa, saErr := partSrv.ServiceAccountRepo.GetByClientRef(syncCtx, cl.GetID())
				if saErr == nil && sa != nil {
					profileID = sa.ProfileID
				}
			}
			if syncErr := events.SyncClientOnHydra(syncCtx, cfg, cliMan, partSrv.ClientRepo, cl, profileID); syncErr != nil {
				log.WithError(syncErr).WithField("client_id", cl.ClientID).Error("failed to sync client to Hydra")
			} else {
				synced++
			}
		}
	}

	log.WithField("count", synced).Info("synced seeded clients to Hydra")
}
