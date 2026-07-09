// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests/testketo"
	internaltests "github.com/antinvestor/service-authentication/pkg/tests"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/client"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/frametests"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/frametests/deps/testnats"
	"github.com/pitabwire/frame/v2/frametests/deps/testpostgres"
	"github.com/pitabwire/frame/v2/frametests/rlstest"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/require"
)

type DepsBuilder struct {
	TenantRepo              repository.TenantRepository
	PartitionRepo           repository.PartitionRepository
	PartitionRoleRepo       repository.PartitionRoleRepository
	AccessRepo              repository.AccessRepository
	AccessRoleRepo          repository.AccessRoleRepository
	PageRepo                repository.PageRepository
	ClientRepo              repository.ClientRepository
	OAuthRecipientRepo      repository.OAuthClientRecipientRepository
	ServiceAccountRepo      repository.ServiceAccountRepository
	AuthorizationPolicyRepo repository.ServiceAccountAuthorizationPolicyRepository
	AuthContractRepo        repository.AuthContractRepository
	ServiceNamespaceRepo    repository.ServiceNamespaceRepository

	PartitionBusiness    business.PartitionBusiness
	TenantBusiness       business.TenantBusiness
	AccessBusiness       business.AccessBusiness
	PageBusiness         business.PageBusiness
	AuthContractBusiness business.AuthContractBusiness

	Server *handlers.TenancyServer
}

func BuildDeps(ctx context.Context, svc *frame.Service, server *handlers.TenancyServer) *DepsBuilder {
	dbPool := svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	workMan := svc.WorkManager()
	cfg := svc.Config().(*aconfig.TenancyConfig)
	eventsMan := svc.EventsManager()

	clientRepo := repository.NewClientRepository(ctx, dbPool, workMan)
	oauthRecipientRepo := repository.NewOAuthClientRecipientRepository(ctx, dbPool, workMan)
	serviceAccountRepo := repository.NewServiceAccountRepository(ctx, dbPool, workMan)
	authorizationPolicyRepo := repository.NewServiceAccountAuthorizationPolicyRepository(ctx, dbPool, workMan)
	authContractRepo := repository.NewAuthContractRepository(dbPool)
	serviceNamespaceRepo := repository.NewServiceNamespaceRepository(ctx, dbPool, workMan)

	depBuilder := &DepsBuilder{
		TenantRepo:              repository.NewTenantRepository(ctx, dbPool, workMan),
		PartitionRepo:           repository.NewPartitionRepository(ctx, dbPool, workMan),
		PartitionRoleRepo:       repository.NewPartitionRoleRepository(ctx, dbPool, workMan),
		AccessRepo:              repository.NewAccessRepository(ctx, dbPool, workMan),
		AccessRoleRepo:          repository.NewAccessRoleRepository(ctx, dbPool, workMan),
		PageRepo:                repository.NewPageRepository(ctx, dbPool, workMan),
		ClientRepo:              clientRepo,
		OAuthRecipientRepo:      oauthRecipientRepo,
		ServiceAccountRepo:      serviceAccountRepo,
		AuthorizationPolicyRepo: authorizationPolicyRepo,
		AuthContractRepo:        authContractRepo,
		ServiceNamespaceRepo:    serviceNamespaceRepo,
		Server:                  server,
	}

	depBuilder.PartitionBusiness = business.NewPartitionBusiness(*cfg, eventsMan, depBuilder.TenantRepo, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo, depBuilder.AccessRepo, clientRepo, serviceAccountRepo)
	depBuilder.TenantBusiness = business.NewTenantBusiness(svc, depBuilder.TenantRepo, depBuilder.PartitionRepo)
	depBuilder.AccessBusiness = business.NewAccessBusiness(svc, eventsMan, depBuilder.AccessRepo, depBuilder.AccessRoleRepo, depBuilder.PartitionRepo, depBuilder.PartitionRoleRepo, serviceNamespaceRepo)
	depBuilder.PageBusiness = business.NewPageBusiness(svc, depBuilder.PageRepo, depBuilder.PartitionRepo)
	authContractBusiness, err := business.NewAuthContractBusiness(
		cfg.GetOauth2AudienceBaseURL(),
		eventsMan,
		depBuilder.PartitionRepo,
		clientRepo,
		oauthRecipientRepo,
		serviceAccountRepo,
		authorizationPolicyRepo,
		serviceNamespaceRepo,
		authContractRepo,
	)
	if err != nil {
		panic(err)
	}
	depBuilder.AuthContractBusiness = authContractBusiness
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
	pg := newTenancyPostgres("service_tenancy",
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
		if dbMan := svc.DatastoreManager(); dbMan != nil {
			dbMan.Close(bgCtx)
		}
		time.Sleep(200 * time.Millisecond)
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
	t.Setenv("OAUTH2_RESOURCE_AUDIENCE", "https://api.example.test/tenancy")
	t.Setenv("OAUTH2_AUDIENCE_BASE_URL", "https://api.example.test")

	cfg, err := config.LoadWithOIDC[aconfig.TenancyConfig](ctx)
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

	// Migrate pins a dedicated connection for its advisory lock (frame
	// >= v1.95) and runs the migration queries on a second one, so a
	// single-connection pool deadlocks before the first table exists.
	testDSLimited := testDS.
		ExtendQuery("pool_max_conns", "2").
		ExtendQuery("pool_min_conns", "0").
		ExtendQuery("pool_max_conn_lifetime", "1s").
		ExtendQuery("pool_max_conn_idle_time", "200ms").
		ExtendQuery("pool_health_check_period", "200ms")
	cfg.DatabasePrimaryURL = []string{testDSLimited.String()}
	cfg.DatabaseReplicaURL = []string{}
	cfg.Oauth2ServiceClientID = "dev_service_tenancy"
	cfg.Oauth2ServiceClientSecret = "hkGiJroO9cDS5eFnuaAV"
	cfg.Oauth2TokenEndpointAuthMethod = "client_secret_post"
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

	cfg.AuthorizationServiceReadURI = bs.ketoReadURI
	cfg.AuthorizationServiceWriteURI = bs.ketoWriteURI

	// The postgres testcontainer user is a SUPERUSER which bypasses RLS even
	// with FORCE ROW LEVEL SECURITY, so tenancy isolation would never be
	// exercised. rlstest drops application connections to an unprivileged
	// role after migration so the suite runs with RLS actually enforced.
	require.NoError(t, rlstest.CreateRole(ctx, testDS.String()))
	rlsProv := rlstest.New()

	ctx, svc := frame.NewServiceWithContext(ctx, frame.WithName("tenancy tests"),
		frame.WithConfig(&cfg), frame.WithTenancyProvider(rlsProv),
		frame.WithDatastore(), frametests.WithNoopDriver())

	auth := svc.SecurityManager().GetAuthorizer(ctx)
	implementation := handlers.NewTenancyServer(ctx, svc, nil)

	// Use a plain HTTP client for Hydra admin API calls (no OAuth2 transport).
	// This matches production (cmd/main.go) where hydraClient is unauthenticated
	// because Hydra admin is cluster-internal and doesn't require OAuth2 tokens.
	hydraClient := client.NewManager(context.Background())

	serviceOptions := []frame.Option{frame.WithRegisterEvents(
		events.NewClientSynchronizationEventHandler(ctx, &cfg, hydraClient, implementation.ClientRepo, implementation.OAuthRecipientRepo, implementation.ServiceAccountRepo),
		events.NewAuthzPartitionSyncEventHandler(implementation.PartitionRepo, implementation.ServiceAccountRepo, implementation.ServiceNamespaceRepo, implementation.AuthorizationPolicyRepo, svc.EventsManager(), auth),
		events.NewAuthzServiceAccountSyncEventHandler(implementation.ServiceAccountRepo, implementation.PartitionRepo, implementation.AuthorizationPolicyRepo, implementation.ServiceNamespaceRepo, implementation.AuthContractRepo, svc.EventsManager(), auth),
		events.NewAuthzAccessSyncEventHandler(implementation.AccessRepo, implementation.AccessRoleRepo, implementation.PartitionRoleRepo, implementation.ServiceNamespaceRepo, auth),
		events.NewTupleWriteEventHandler(auth),
		events.NewTupleDeleteEventHandler(auth),
	)}

	serviceOptions = append(serviceOptions, frame.WithHTTPHandler(implementation.NewSecureRouterV1()))

	svc.Init(ctx, serviceOptions...)

	err = repository.Migrate(
		ctx,
		svc.DatastoreManager(),
		"../../migrations/0001",
	)
	require.NoError(t, err)
	svc.DatastoreManager().RemovePool(ctx, datastore.DefaultMigrationPoolName)

	now := time.Now().UTC()
	for _, namespace := range []*models.ServiceNamespace{
		{
			Namespace:    "service_profile",
			Permissions:  data.JSONMap{"values": []string{"profile_update", "profile_view"}},
			RoleBindings: data.JSONMap{"owner": []string{"profile_update", "profile_view"}},
			RegisteredAt: &now,
		},
		{
			Namespace: "service_tenancy",
			Permissions: data.JSONMap{"values": []string{
				"access_manage", "access_view", "client_manage", "client_view", "page_manage", "page_view",
				"partition_manage", "partition_view", "permission_grant", "role_manage", "service_account_manage",
				"service_account_view", "tenant_manage", "tenant_view",
			}},
			RoleBindings: data.JSONMap{"owner": []string{"tenant_manage", "tenant_view"}},
			RegisteredAt: &now,
		},
	} {
		_, registerErr := implementation.ServiceNamespaceRepo.RegisterOwned(ctx, namespace, "test-service-account")
		require.NoError(t, registerErr)
	}

	// Migration ran as superuser; grant the restricted role access to the
	// migrated tables, then switch all application queries to it.
	require.NoError(t, rlstest.GrantAll(ctx, testDS.String()))
	rlsProv.Enable()

	// WithNoopDriver: Run completes after startups (events/queues) finish.
	// No goroutine — that is the test-driver contract (frame v2.0.3+).
	require.NoError(t, svc.Run(ctx, ""))

	// Sync seeded records to Hydra so SA credentials work for service-to-service auth.
	// Must happen after migrations and before any OAuth2-authenticated calls.
	syncSeededRecordsToHydra(ctx, &cfg, implementation)

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
	namespaceRepo := repository.NewServiceNamespaceRepository(
		ctx,
		svc.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName),
		svc.WorkManager(),
	)
	namespaces, err := namespaceRepo.ListAll(ctx)
	bs.Require().NoError(err, "failed to load registered permission namespaces")

	tuples := authz.BuildRoleTuples(tenancyPath, profileID, role, namespaces)
	err = auth.WriteTuples(ctx, tuples)
	bs.Require().NoError(err, "failed to seed tenant role")
}

// syncSeededRecordsToHydra syncs all seeded OAuth client records to Hydra after
// migrations. It uses a plain HTTP client (no OAuth2 transport)
// because the service's own OAuth2 client (dev_service_tenancy) hasn't been
// registered on Hydra yet — the Hydra admin API doesn't require auth.
// Once the seeded clients are registered, the service's OAuth2-authenticated
// HTTP client will be able to obtain tokens for subsequent event handlers.
func syncSeededRecordsToHydra(ctx context.Context, cfg *aconfig.TenancyConfig, partSrv *handlers.TenancyServer) {
	log := util.Log(ctx)
	syncCtx := security.SkipTenancyChecksOnClaims(ctx)

	// Plain HTTP client — context.Background() has no OAuth2 config,
	// so client.NewManager won't wrap requests with OAuth2 transport.
	plainCli := client.NewManager(context.Background())
	defer plainCli.Close()

	// Sync clients, including service account clients like dev_service_tenancy.
	clientQuery := data.NewSearchQuery(
		data.WithSearchLimit(200),
		data.WithSearchFiltersAndByValue(map[string]any{"synced_at IS NULL": ""}),
	)
	clientResult, err := partSrv.ClientRepo.Search(syncCtx, clientQuery)
	if err != nil {
		log.WithError(err).Error("failed to search unsynced clients for Hydra sync")
		return
	}

	clientsSynced := 0
	for {
		result, ok := clientResult.ReadResult(syncCtx)
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
			if syncErr := events.SyncClientOnHydra(syncCtx, cfg, plainCli, partSrv.ClientRepo, partSrv.OAuthRecipientRepo, cl, profileID); syncErr != nil {
				log.WithError(syncErr).WithField("client_id", cl.ClientID).Error("failed to sync client to Hydra")
			} else {
				clientsSynced++
			}
		}
	}

	log.WithField("count", clientsSynced).Info("synced seeded clients to Hydra")
}
