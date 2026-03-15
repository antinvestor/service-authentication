package authz_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests/testketo"
	"github.com/pitabwire/frame/config"
	"github.com/pitabwire/frame/frametests"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testpostgres"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/frame/security/authorizer"
	"github.com/stretchr/testify/suite"
)

func testTenancyPath() string {
	return fmt.Sprintf("%s/%s", "tenant1", "partition1")
}

// ---------------------------------------------------------------------------
// Test suite with real Keto
// ---------------------------------------------------------------------------

type MiddlewareTestSuite struct {
	frametests.FrameBaseTestSuite
	ketoReadURI  string
	ketoWriteURI string
}

func initMiddlewareResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.New()
	keto := testketo.NewWithOpts(
		definition.WithEnableLogging(false),
		definition.WithDependancies(pg),
	)
	return []definition.TestResource{pg, keto}
}

func (s *MiddlewareTestSuite) SetupSuite() {
	s.InitResourceFunc = initMiddlewareResources
	s.FrameBaseTestSuite.SetupSuite()

	ctx := s.T().Context()
	var ketoDep definition.DependancyConn
	for _, res := range s.Resources() {
		if res.Name() == testketo.ImageName {
			ketoDep = res
			break
		}
	}
	s.Require().NotNil(ketoDep, "keto dependency should be available")

	writeURL, err := url.Parse(string(ketoDep.GetDS(ctx)))
	s.Require().NoError(err)
	s.ketoWriteURI = writeURL.Host

	readPort, err := ketoDep.PortMapping(ctx, "4466/tcp")
	s.Require().NoError(err)
	s.ketoReadURI = fmt.Sprintf("%s:%s", writeURL.Hostname(), readPort)
}

func (s *MiddlewareTestSuite) newAuthorizer() security.Authorizer {
	cfg := &config.ConfigurationDefault{
		AuthorizationServiceReadURI:  s.ketoReadURI,
		AuthorizationServiceWriteURI: s.ketoWriteURI,
	}
	return authorizer.NewKetoAdapter(cfg, nil)
}

func (s *MiddlewareTestSuite) ctxWithClaims(subjectID string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID:    "tenant1",
		PartitionID: "partition1",
	}
	claims.Subject = subjectID
	return claims.ClaimsToContext(context.Background())
}

func (s *MiddlewareTestSuite) ctxWithSystemInternalClaims(subjectID string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID:    "tenant1",
		PartitionID: "partition1",
		Roles:       []string{"internal"},
	}
	claims.Subject = subjectID
	return claims.ClaimsToContext(context.Background())
}

// seedRole writes a role tuple in service_tenancy namespace.
// Only the role tuple is needed — Keto evaluates OPL permits for permission resolution.
func (s *MiddlewareTestSuite) seedRole(auth security.Authorizer, tenancyPath, profileID, role string) {
	tuples := authz.BuildRoleTuples(tenancyPath, profileID, role)
	err := auth.WriteTuples(s.T().Context(), tuples)
	s.Require().NoError(err)
}

func TestMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}

// ---------------------------------------------------------------------------
// FunctionChecker (middleware) tests — only checks service_tenancy permissions
// ---------------------------------------------------------------------------

func (s *MiddlewareTestSuite) TestOwnerHasAllPermissions() {
	auth := s.newAuthorizer()
	s.seedRole(auth, testTenancyPath(), "user1", authz.RoleOwner)

	mw := authz.NewMiddleware(auth)
	ctx := s.ctxWithClaims("user1")

	s.NoError(mw.CanTenantManage(ctx))
	s.NoError(mw.CanTenantView(ctx))
	s.NoError(mw.CanPartitionManage(ctx))
	s.NoError(mw.CanPartitionView(ctx))
	s.NoError(mw.CanAccessManage(ctx))
	s.NoError(mw.CanRolesManage(ctx))
	s.NoError(mw.CanPagesManage(ctx))
	s.NoError(mw.CanPagesView(ctx))
	s.NoError(mw.CanPermissionGrant(ctx))
}

func (s *MiddlewareTestSuite) TestAdminPermissions() {
	auth := s.newAuthorizer()
	s.seedRole(auth, testTenancyPath(), "user2", authz.RoleAdmin)

	mw := authz.NewMiddleware(auth)
	ctx := s.ctxWithClaims("user2")

	// Admin cannot manage tenant
	s.Error(mw.CanTenantManage(ctx))

	// Admin can do everything else
	s.NoError(mw.CanTenantView(ctx))
	s.NoError(mw.CanPartitionManage(ctx))
	s.NoError(mw.CanPartitionView(ctx))
	s.NoError(mw.CanAccessManage(ctx))
	s.NoError(mw.CanRolesManage(ctx))
	s.NoError(mw.CanPagesManage(ctx))
	s.NoError(mw.CanPagesView(ctx))
	s.NoError(mw.CanPermissionGrant(ctx))
}

func (s *MiddlewareTestSuite) TestMemberPermissions() {
	auth := s.newAuthorizer()
	s.seedRole(auth, testTenancyPath(), "user3", authz.RoleMember)

	mw := authz.NewMiddleware(auth)
	ctx := s.ctxWithClaims("user3")

	// Member can only view
	s.NoError(mw.CanTenantView(ctx))
	s.NoError(mw.CanPartitionView(ctx))
	s.NoError(mw.CanPagesView(ctx))

	// Member cannot manage
	s.Error(mw.CanTenantManage(ctx))
	s.Error(mw.CanPartitionManage(ctx))
	s.Error(mw.CanAccessManage(ctx))
	s.Error(mw.CanRolesManage(ctx))
	s.Error(mw.CanPagesManage(ctx))
	s.Error(mw.CanPermissionGrant(ctx))
}

func (s *MiddlewareTestSuite) TestNoClaims() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	err := mw.CanTenantView(context.Background())
	s.ErrorIs(err, authorizer.ErrInvalidSubject)
}

func (s *MiddlewareTestSuite) TestNoTenant() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	claims := &security.AuthenticationClaims{}
	claims.Subject = "user1"
	ctx := claims.ClaimsToContext(context.Background())
	err := mw.CanTenantView(ctx)
	s.ErrorIs(err, authorizer.ErrInvalidObject)
}

// ---------------------------------------------------------------------------
// TenancyAccessChecker tests — data access layer
// ---------------------------------------------------------------------------

func (s *MiddlewareTestSuite) TestAccessChecker_MemberAllowed() {
	auth := s.newAuthorizer()
	checker := authorizer.NewTenancyAccessChecker(auth, authz.NamespaceTenancyAccess)

	// Seed member tuple in tenancy_access
	err := auth.WriteTuple(s.T().Context(), authz.BuildAccessTuple(testTenancyPath(), "member-user"))
	s.Require().NoError(err)

	ctx := s.ctxWithClaims("member-user")
	s.NoError(checker.CheckAccess(ctx))
}

func (s *MiddlewareTestSuite) TestAccessChecker_ServiceBotAllowed() {
	auth := s.newAuthorizer()
	checker := authorizer.NewTenancyAccessChecker(auth, authz.NamespaceTenancyAccess)

	// Seed service tuple in tenancy_access
	err := auth.WriteTuple(s.T().Context(), authz.BuildServiceAccessTuple(testTenancyPath(), "bot-user"))
	s.Require().NoError(err)

	ctx := s.ctxWithSystemInternalClaims("bot-user")
	s.NoError(checker.CheckAccess(ctx))
}

func (s *MiddlewareTestSuite) TestAccessChecker_NoTupleDenied() {
	auth := s.newAuthorizer()
	checker := authorizer.NewTenancyAccessChecker(auth, authz.NamespaceTenancyAccess)

	ctx := s.ctxWithClaims("unknown-user")
	s.Error(checker.CheckAccess(ctx))
}

// ---------------------------------------------------------------------------
// Service bot via explicit permissions — full two-layer check
// ---------------------------------------------------------------------------

func (s *MiddlewareTestSuite) TestServiceBotViaExplicitPermissions() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)
	accessChecker := authorizer.NewTenancyAccessChecker(auth, authz.NamespaceTenancyAccess)

	// Step 1: Grant the bot service access in tenancy_access (Plane 1).
	err := auth.WriteTuple(s.T().Context(), authz.BuildServiceAccessTuple(testTenancyPath(), "service-bot"))
	s.Require().NoError(err)

	// Step 2: Write explicit per-permission tuples (Plane 2).
	permTuples := authz.BuildServicePermissionTuples(
		testTenancyPath(), "service-bot", authz.NamespaceTenancy, authz.AllServicePermissions(),
	)
	err = auth.WriteTuples(s.T().Context(), permTuples)
	s.Require().NoError(err)

	botCtx := s.ctxWithSystemInternalClaims("service-bot")

	// Layer 1: Access check passes
	s.NoError(accessChecker.CheckAccess(botCtx))

	// Layer 2: Functional permissions resolved through explicit granted_ tuples
	s.NoError(mw.CanTenantManage(botCtx))
	s.NoError(mw.CanTenantView(botCtx))
	s.NoError(mw.CanPartitionManage(botCtx))
	s.NoError(mw.CanPartitionView(botCtx))
	s.NoError(mw.CanAccessManage(botCtx))
	s.NoError(mw.CanRolesManage(botCtx))
	s.NoError(mw.CanPagesManage(botCtx))
	s.NoError(mw.CanPagesView(botCtx))
	s.NoError(mw.CanPermissionGrant(botCtx))
}

func (s *MiddlewareTestSuite) TestServiceBotPartialPermissions() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	// Grant only view permissions — no manage
	err := auth.WriteTuple(s.T().Context(), authz.BuildServiceAccessTuple(testTenancyPath(), "limited-bot"))
	s.Require().NoError(err)

	viewPerms := []string{authz.PermissionTenantView, authz.PermissionPartitionView, authz.PermissionPagesView}
	permTuples := authz.BuildServicePermissionTuples(testTenancyPath(), "limited-bot", authz.NamespaceTenancy, viewPerms)
	err = auth.WriteTuples(s.T().Context(), permTuples)
	s.Require().NoError(err)

	botCtx := s.ctxWithSystemInternalClaims("limited-bot")

	// View permissions granted
	s.NoError(mw.CanTenantView(botCtx))
	s.NoError(mw.CanPartitionView(botCtx))
	s.NoError(mw.CanPagesView(botCtx))

	// Manage permissions denied
	s.Error(mw.CanTenantManage(botCtx))
	s.Error(mw.CanPartitionManage(botCtx))
	s.Error(mw.CanAccessManage(botCtx))
	s.Error(mw.CanPermissionGrant(botCtx))
}

func (s *MiddlewareTestSuite) TestDirectPermissionGrant() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	// User has a direct permission grant (uses granted_ prefix relation)
	err := auth.WriteTuple(s.T().Context(), security.RelationTuple{
		Object:   security.ObjectRef{Namespace: authz.NamespaceTenancy, ID: testTenancyPath()},
		Relation: authz.GrantedPagesManage,
		Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: "user4"},
	})
	s.Require().NoError(err)

	ctx := s.ctxWithClaims("user4")

	// Direct grant works (OPL permit checks granted_pages_manage relation)
	s.NoError(mw.CanPagesManage(ctx))

	// Other permissions still denied
	s.Error(mw.CanTenantManage(ctx))
	s.Error(mw.CanAccessManage(ctx))
}
