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

const (
	testTenantID    = "tenant1"
	testPartitionID = "partition1"
)

var testTenancyPath = fmt.Sprintf("%s/%s", testTenantID, testPartitionID)

// ---------------------------------------------------------------------------
// Test suite with real Keto
// ---------------------------------------------------------------------------

type MiddlewareTestSuite struct {
	frametests.FrameBaseTestSuite
	ketoReadURI  string
	ketoWriteURI string
}

func initMiddlewareResources(_ context.Context) []definition.TestResource {
	pg := testpostgres.NewWithOpts("authz_middleware_test",
		definition.WithUserName("ant"),
		definition.WithCredential("s3cr3t"),
		definition.WithEnableLogging(false),
		definition.WithUseHostMode(false),
	)
	keto := testketo.NewWithOpts(
		definition.WithDependancies(pg),
		definition.WithEnableLogging(false),
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
		TenantID:    testTenantID,
		PartitionID: testPartitionID,
	}
	claims.Subject = subjectID
	return claims.ClaimsToContext(context.Background())
}

func (s *MiddlewareTestSuite) seedRole(auth security.Authorizer, tenancyPath, profileID, role string) {
	// Write the role tuple and all materialised permission tuples.
	// We only write to the tenancy namespace (not all service namespaces)
	// since these tests only check tenancy permissions.
	permissions := authz.RolePermissions[role]
	tuples := make([]security.RelationTuple, 0, 1+len(permissions))

	tuples = append(tuples, security.RelationTuple{
		Object:   security.ObjectRef{Namespace: authz.NamespaceTenancy, ID: tenancyPath},
		Relation: role,
		Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: profileID},
	})

	for _, perm := range permissions {
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: authz.NamespaceTenancy, ID: tenancyPath},
			Relation: perm,
			Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: profileID},
		})
	}

	err := auth.WriteTuples(s.T().Context(), tuples)
	s.Require().NoError(err)
}

func TestMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func (s *MiddlewareTestSuite) TestOwnerHasAllPermissions() {
	auth := s.newAuthorizer()
	s.seedRole(auth, testTenancyPath, "user1", authz.RoleOwner)

	mw := authz.NewMiddleware(auth)
	ctx := s.ctxWithClaims("user1")

	s.NoError(mw.CanManageTenant(ctx))
	s.NoError(mw.CanViewTenant(ctx))
	s.NoError(mw.CanManagePartition(ctx))
	s.NoError(mw.CanViewPartition(ctx))
	s.NoError(mw.CanManageAccess(ctx))
	s.NoError(mw.CanManageRoles(ctx))
	s.NoError(mw.CanManagePages(ctx))
	s.NoError(mw.CanViewPages(ctx))
	s.NoError(mw.CanGrantPermission(ctx))
}

func (s *MiddlewareTestSuite) TestAdminPermissions() {
	auth := s.newAuthorizer()
	s.seedRole(auth, testTenancyPath, "user2", authz.RoleAdmin)

	mw := authz.NewMiddleware(auth)
	ctx := s.ctxWithClaims("user2")

	// Admin cannot manage tenant
	s.Error(mw.CanManageTenant(ctx))

	// Admin can do everything else
	s.NoError(mw.CanViewTenant(ctx))
	s.NoError(mw.CanManagePartition(ctx))
	s.NoError(mw.CanViewPartition(ctx))
	s.NoError(mw.CanManageAccess(ctx))
	s.NoError(mw.CanManageRoles(ctx))
	s.NoError(mw.CanManagePages(ctx))
	s.NoError(mw.CanViewPages(ctx))
	s.NoError(mw.CanGrantPermission(ctx))
}

func (s *MiddlewareTestSuite) TestMemberPermissions() {
	auth := s.newAuthorizer()
	s.seedRole(auth, testTenancyPath, "user3", authz.RoleMember)

	mw := authz.NewMiddleware(auth)
	ctx := s.ctxWithClaims("user3")

	// Member can only view
	s.NoError(mw.CanViewTenant(ctx))
	s.NoError(mw.CanViewPartition(ctx))
	s.NoError(mw.CanViewPages(ctx))

	// Member cannot manage
	s.Error(mw.CanManageTenant(ctx))
	s.Error(mw.CanManagePartition(ctx))
	s.Error(mw.CanManageAccess(ctx))
	s.Error(mw.CanManageRoles(ctx))
	s.Error(mw.CanManagePages(ctx))
	s.Error(mw.CanGrantPermission(ctx))
}

func (s *MiddlewareTestSuite) TestNoClaims() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	err := mw.CanViewTenant(context.Background())
	s.ErrorIs(err, authorizer.ErrInvalidSubject)
}

func (s *MiddlewareTestSuite) TestNoTenant() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	claims := &security.AuthenticationClaims{}
	claims.Subject = "user1"
	ctx := claims.ClaimsToContext(context.Background())
	err := mw.CanViewTenant(ctx)
	s.ErrorIs(err, authorizer.ErrInvalidObject)
}

func (s *MiddlewareTestSuite) seedServiceBridgeTuples(auth security.Authorizer, tenancyPath string) {
	// Write the tenancy-namespace bridge tuples only (test Keto doesn't have
	// payment, ledger, etc.). This mirrors what BuildServiceInheritanceTuples
	// does for the tenancy namespace specifically.
	servicePermissions := authz.RolePermissions[authz.RoleService]
	ns := authz.NamespaceTenancy

	tuples := make([]security.RelationTuple, 0, 1+len(servicePermissions))

	// Cross-namespace bridge: tenancy#service ← tenancy_access#service
	tuples = append(tuples, security.RelationTuple{
		Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
		Relation: authz.RoleService,
		Subject:  security.SubjectRef{Namespace: authz.NamespaceTenancyAccess, ID: tenancyPath, Relation: authz.RoleService},
	})

	// Permission bridges: tenancy#perm ← tenancy#service
	for _, perm := range servicePermissions {
		tuples = append(tuples, security.RelationTuple{
			Object:   security.ObjectRef{Namespace: ns, ID: tenancyPath},
			Relation: perm,
			Subject:  security.SubjectRef{Namespace: ns, ID: tenancyPath, Relation: authz.RoleService},
		})
	}

	err := auth.WriteTuples(s.T().Context(), tuples)
	s.Require().NoError(err)
}

func (s *MiddlewareTestSuite) TestServiceBotViaSubjectSets() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	// Step 1: Write bridge tuples (normally done at partition creation).
	// These link tenancy_access#service → tenancy#service → tenancy#permission.
	s.seedServiceBridgeTuples(auth, testTenancyPath)

	// Step 2: Grant the bot service access in tenancy_access (one tuple per bot).
	err := auth.WriteTuple(s.T().Context(), authz.BuildServiceAccessTuple(testTenancyPath, "service-bot"))
	s.Require().NoError(err)

	// Step 3: Verify the bot gets all permissions through Keto subject set resolution.
	botCtx := s.ctxWithClaims("service-bot")

	s.NoError(mw.CanManageTenant(botCtx))
	s.NoError(mw.CanViewTenant(botCtx))
	s.NoError(mw.CanManagePartition(botCtx))
	s.NoError(mw.CanViewPartition(botCtx))
	s.NoError(mw.CanManageAccess(botCtx))
	s.NoError(mw.CanManageRoles(botCtx))
	s.NoError(mw.CanManagePages(botCtx))
	s.NoError(mw.CanViewPages(botCtx))
	s.NoError(mw.CanGrantPermission(botCtx))
}

func (s *MiddlewareTestSuite) TestDirectPermissionGrant() {
	auth := s.newAuthorizer()
	mw := authz.NewMiddleware(auth)

	// User has no role but a direct permission grant
	err := auth.WriteTuple(s.T().Context(), security.RelationTuple{
		Object:   security.ObjectRef{Namespace: authz.NamespaceTenancy, ID: testTenancyPath},
		Relation: authz.PermissionManagePages,
		Subject:  security.SubjectRef{Namespace: authz.NamespaceProfile, ID: "user4"},
	})
	s.Require().NoError(err)

	ctx := s.ctxWithClaims("user4")

	// Direct grant works
	s.NoError(mw.CanManagePages(ctx))

	// Other permissions still denied
	s.Error(mw.CanManageTenant(ctx))
	s.Error(mw.CanManageAccess(ctx))
}
