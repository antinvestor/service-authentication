package business_test

import (
	"testing"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

type BusinessTestSuite struct {
	tests.BaseTestSuite
}

func TestBusinessTestSuite(t *testing.T) {
	suite.Run(t, new(BusinessTestSuite))
}

func (s *BusinessTestSuite) SetupSuite() {
	s.BaseTestSuite.SetupSuite()
	s.CreateSuiteService()
}

// createTestTenant creates a tenant via repo without claims (unscoped).
func (s *BusinessTestSuite) createTestTenant(name string) *models.Tenant {
	tenant := &models.Tenant{Name: name}
	err := s.SuiteDeps.TenantRepo.Create(s.SuiteCtx, tenant)
	s.Require().NoError(err)
	return tenant
}

// createTestPartition creates a partition with PartitionID = its own ID (matching production pattern).
func (s *BusinessTestSuite) createTestPartition(tenantID string) *models.Partition {
	partitionID := util.IDString()
	partition := &models.Partition{
		Name: "P",
		BaseModel: data.BaseModel{
			ID:          partitionID,
			TenantID:    tenantID,
			PartitionID: partitionID, // self-referencing, matches production migration pattern
		},
	}
	err := s.SuiteDeps.PartitionRepo.Create(s.SuiteCtx, partition)
	s.Require().NoError(err)
	return partition
}

// setupTenantAndPartition creates a tenant+partition and returns claims-scoped context.
func (s *BusinessTestSuite) setupTenantAndPartition() *models.Partition {
	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())
	return partition
}

// ========================
// Tenant Business Tests
// ========================

func (s *BusinessTestSuite) TestCreateTenant() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	profileID := util.IDString()
	tenantID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenantID, tenantID, profileID)

	resp, err := deps.TenantBusiness.CreateTenant(ctx, &partitionv1.CreateTenantRequest{
		Name:        "Test Tenant",
		Description: "A test tenant",
	})

	s.Require().NoError(err)
	s.Require().NotEmpty(resp.Id)
	s.Require().Equal("Test Tenant", resp.Name)
	s.Require().Equal("A test tenant", resp.Description)
}

func (s *BusinessTestSuite) TestGetTenant() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("Get Me")
	tenant.Description = "Desc"

	// Match the scoping fields from the unscoped create
	ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

	fetched, err := deps.TenantBusiness.GetTenant(ctx, tenant.GetID())
	s.Require().NoError(err)
	s.Equal(tenant.GetID(), fetched.Id)
	s.Equal("Get Me", fetched.Name)
}

func (s *BusinessTestSuite) TestGetTenant_NotFound() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

	_, err := deps.TenantBusiness.GetTenant(ctx, "nonexistent")
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestUpdateTenant_Name() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("OldName")
	ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

	updated, err := deps.TenantBusiness.UpdateTenant(ctx, &partitionv1.UpdateTenantRequest{
		Id:   tenant.GetID(),
		Name: "NewName",
	})

	s.Require().NoError(err)
	s.Equal("NewName", updated.Name)
}

func (s *BusinessTestSuite) TestUpdateTenant_Properties() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("PropsTest")
	ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

	props, _ := structpb.NewStruct(map[string]any{"key": "value"})

	updated, err := deps.TenantBusiness.UpdateTenant(ctx, &partitionv1.UpdateTenantRequest{
		Id:         tenant.GetID(),
		Properties: props,
	})

	s.Require().NoError(err)
	s.NotNil(updated.Properties)

	fetchedProps := updated.Properties.AsMap()
	s.Equal("value", fetchedProps["key"])
}

func (s *BusinessTestSuite) TestListTenant() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	// Create in unscoped context
	for _, n := range []string{"L1", "L2"} {
		s.createTestTenant(n)
	}

	// ListTenant uses profile_id from claims Subject as search filter.
	// Use claims with empty tenant/partition to match unscoped tenants,
	// and empty Subject to avoid profile_id filtering.
	claims := &security.AuthenticationClaims{
		AccessID:  util.IDString(),
		SessionID: util.IDString(),
		DeviceID:  "test-device",
	}
	ctx = claims.ClaimsToContext(ctx)

	tenants, err := deps.TenantBusiness.ListTenant(ctx, &partitionv1.ListTenantRequest{})
	s.Require().NoError(err)
	s.GreaterOrEqual(len(tenants), 2)
}

// ========================
// Partition Business Tests
// ========================

func (s *BusinessTestSuite) TestCreatePartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("CP Tenant")

	claims := &security.AuthenticationClaims{
		TenantID:    tenant.TenantID,
		PartitionID: tenant.PartitionID,
		AccessID:    util.IDString(),
		SessionID:   util.IDString(),
		DeviceID:    "test-device",
	}
	ctx = claims.ClaimsToContext(ctx)

	resp, err := deps.PartitionBusiness.CreatePartition(ctx, &partitionv1.CreatePartitionRequest{
		TenantId:    tenant.GetID(),
		Name:        "Partition A",
		Description: "desc",
	})

	s.Require().NoError(err)
	s.NotEmpty(resp.Id)
	s.Equal("Partition A", resp.Name)
}

func (s *BusinessTestSuite) TestCreatePartition_InvalidTenant() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	claims := &security.AuthenticationClaims{
		TenantID:    util.IDString(),
		PartitionID: util.IDString(),
		AccessID:    util.IDString(),
		SessionID:   util.IDString(),
		DeviceID:    "test-device",
	}
	ctx = claims.ClaimsToContext(ctx)

	_, err := deps.PartitionBusiness.CreatePartition(ctx, &partitionv1.CreatePartitionRequest{
		TenantId: "nonexistent-tenant",
		Name:     "Bad",
	})
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestGetPartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("GP")
	partition := s.createTestPartition(tenant.GetID())
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	fetched, err := deps.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{Id: partition.GetID()})
	s.Require().NoError(err)
	s.Equal(partition.GetID(), fetched.Id)
}

func (s *BusinessTestSuite) TestGetPartition_ServiceMatrix() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("SM")
	partition := s.createTestPartition(tenant.GetID())

	partition.Properties = data.JSONMap{
		"client_secret": "top-secret",
	}
	_, err := deps.PartitionRepo.Update(ctx, partition, "properties")
	s.Require().NoError(err)

	// Set subject to "service_matrix" to trigger enrichment
	claims := &security.AuthenticationClaims{
		TenantID:    tenant.GetID(),
		PartitionID: partition.GetID(),
		AccessID:    util.IDString(),
		SessionID:   util.IDString(),
		DeviceID:    "test-device",
	}
	claims.Subject = "service_matrix"
	ctx = claims.ClaimsToContext(ctx)

	fetched, err := deps.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{Id: partition.GetID()})
	s.Require().NoError(err)
	s.Equal("top-secret", fetched.Properties.AsMap()["client_secret"])
	s.NotEmpty(fetched.Properties.AsMap()["client_discovery_uri"])
}

func (s *BusinessTestSuite) TestGetPartition_NoClaims() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("NC")
	partition := s.createTestPartition(tenant.GetID())

	_, err := deps.PartitionBusiness.GetPartition(ctx, &partitionv1.GetPartitionRequest{Id: partition.GetID()})
	s.Require().Error(err)
	s.Contains(err.Error(), "known entities")
}

func (s *BusinessTestSuite) TestUpdatePartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("UP")
	partition := s.createTestPartition(tenant.GetID())
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	updated, err := deps.PartitionBusiness.UpdatePartition(ctx, &partitionv1.UpdatePartitionRequest{
		Id:          partition.GetID(),
		Name:        "Updated Name",
		Description: "Updated Desc",
	})
	s.Require().NoError(err)
	s.Equal("Updated Name", updated.Name)
	s.Equal("Updated Desc", updated.Description)
}

func (s *BusinessTestSuite) TestListPartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("LP")
	partition := s.createTestPartition(tenant.GetID())

	// ListPartition applies TenancyPartition scope and buildSearchQuery adds
	// profile_id filter from claims Subject. Use claims with matching
	// tenant+partition but no Subject to avoid the profile_id filter.
	claims := &security.AuthenticationClaims{
		TenantID:    tenant.GetID(),
		PartitionID: partition.GetID(),
		AccessID:    util.IDString(),
		SessionID:   util.IDString(),
		DeviceID:    "test-device",
	}
	ctx = claims.ClaimsToContext(ctx)

	partitions, err := deps.PartitionBusiness.ListPartition(ctx, &partitionv1.ListPartitionRequest{})
	s.Require().NoError(err)
	s.GreaterOrEqual(len(partitions), 1)
	s.Equal(partition.GetID(), partitions[0].GetId())
}

func (s *BusinessTestSuite) TestGetPartitionParents() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("PP")
	parent := s.createTestPartition(tenant.GetID())

	childID := util.IDString()
	child := &models.Partition{
		Name:     "Child",
		ParentID: parent.GetID(),
		BaseModel: data.BaseModel{
			ID:          childID,
			TenantID:    tenant.GetID(),
			PartitionID: childID,
		},
	}
	err := deps.PartitionRepo.Create(ctx, child)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), childID, util.IDString())

	parents, err := deps.PartitionBusiness.GetPartitionParents(ctx, &partitionv1.GetPartitionParentsRequest{Id: childID})
	s.Require().NoError(err)
	s.GreaterOrEqual(len(parents), 1)
	s.Equal(parent.GetID(), parents[0].Id)
}

// ========================
// Partition Role Tests
// ========================

func (s *BusinessTestSuite) TestCreatePartitionRole() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("PR")
	partition := s.createTestPartition(tenant.GetID())
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	role, err := deps.PartitionBusiness.CreatePartitionRole(ctx, &partitionv1.CreatePartitionRoleRequest{
		PartitionId: partition.GetID(),
		Name:        "admin",
	})
	s.Require().NoError(err)
	s.Equal("admin", role.Name)
}

func (s *BusinessTestSuite) TestListPartitionRoles() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("LPR")
	partition := s.createTestPartition(tenant.GetID())

	for _, name := range []string{"admin", "viewer"} {
		role := &models.PartitionRole{
			Name: name,
			BaseModel: data.BaseModel{
				TenantID:    tenant.GetID(),
				PartitionID: partition.GetID(),
			},
		}
		err := deps.PartitionRoleRepo.Create(ctx, role)
		s.Require().NoError(err)
	}

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	resp, err := deps.PartitionBusiness.ListPartitionRoles(ctx, &partitionv1.ListPartitionRoleRequest{
		PartitionId: partition.GetID(),
	})
	s.Require().NoError(err)
	s.GreaterOrEqual(len(resp.Data), 2)
}

func (s *BusinessTestSuite) TestRemovePartitionRole() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("RPR")
	partition := s.createTestPartition(tenant.GetID())

	role := &models.PartitionRole{
		Name: "doomed",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.PartitionRoleRepo.Create(ctx, role)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	err = deps.PartitionBusiness.RemovePartitionRole(ctx, &partitionv1.RemovePartitionRoleRequest{
		Id: role.GetID(),
	})
	s.Require().NoError(err)

	_, err = deps.PartitionRoleRepo.GetByID(ctx, role.GetID())
	s.Require().Error(err)
}

// ========================
// Access Business Tests
// ========================

func (s *BusinessTestSuite) newGetPageByPartitionAndName(partitionID, name string) *partitionv1.GetPageRequest {
	req := &partitionv1.GetPageRequest{}
	req.SetPartitionId(partitionID)
	req.SetName(name)
	return req
}

func (s *BusinessTestSuite) newCreateAccessReq(partitionID, profileID string) *partitionv1.CreateAccessRequest {
	req := &partitionv1.CreateAccessRequest{}
	req.SetPartitionId(partitionID)
	req.SetProfileId(profileID)
	return req
}

func (s *BusinessTestSuite) newGetAccessByIDReq(accessID string) *partitionv1.GetAccessRequest {
	req := &partitionv1.GetAccessRequest{}
	req.SetAccessId(accessID)
	return req
}

func (s *BusinessTestSuite) newGetAccessByPartitionProfileReq(partitionID, profileID string) *partitionv1.GetAccessRequest {
	req := &partitionv1.GetAccessRequest{}
	req.SetPartitionId(partitionID)
	req.SetProfileId(profileID)
	return req
}

func (s *BusinessTestSuite) TestCreateAccess() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("CA")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	resp, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)
	s.NotEmpty(resp.GetId())
}

func (s *BusinessTestSuite) TestCreateAccess_Idempotent() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("CAI")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	req := s.newCreateAccessReq(partition.GetID(), profileID)

	first, err := deps.AccessBusiness.CreateAccess(ctx, req)
	s.Require().NoError(err)

	second, err := deps.AccessBusiness.CreateAccess(ctx, req)
	s.Require().NoError(err)
	s.Equal(first.GetId(), second.GetId())
}

func (s *BusinessTestSuite) TestGetAccess_ByID() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("GAI")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)

	fetched, err := deps.AccessBusiness.GetAccess(ctx, s.newGetAccessByIDReq(created.GetId()))
	s.Require().NoError(err)
	s.Equal(created.GetId(), fetched.GetId())
	s.Equal(partition.GetID(), fetched.GetPartition().GetId())
}

func (s *BusinessTestSuite) TestGetAccess_ByPartitionAndProfile() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("GAPP")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)

	fetched, err := deps.AccessBusiness.GetAccess(ctx, s.newGetAccessByPartitionProfileReq(partition.GetID(), profileID))
	s.Require().NoError(err)
	s.Equal(created.GetId(), fetched.GetId())
}

func (s *BusinessTestSuite) TestRemoveAccess() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("RA")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)

	removeReq := &partitionv1.RemoveAccessRequest{}
	removeReq.SetId(created.GetId())
	err = deps.AccessBusiness.RemoveAccess(ctx, removeReq)
	s.Require().NoError(err)

	_, err = deps.AccessBusiness.GetAccess(ctx, s.newGetAccessByIDReq(created.GetId()))
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestCreateAccessRole() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("CAR")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)

	role := &models.PartitionRole{
		Name: "editor",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err = deps.PartitionRoleRepo.Create(ctx, role)
	s.Require().NoError(err)

	createRoleReq := &partitionv1.CreateAccessRoleRequest{}
	createRoleReq.SetAccessId(created.GetId())
	createRoleReq.SetPartitionRoleId(role.GetID())
	resp, err := deps.AccessBusiness.CreateAccessRole(ctx, createRoleReq)
	s.Require().NoError(err)
	s.NotEmpty(resp.GetId())
	s.Equal(created.GetId(), resp.GetAccessId())
}

func (s *BusinessTestSuite) TestListAccessRoles() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("LAR")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)

	for _, roleName := range []string{"admin", "viewer"} {
		role := &models.PartitionRole{
			Name: roleName,
			BaseModel: data.BaseModel{
				TenantID:    tenant.GetID(),
				PartitionID: partition.GetID(),
			},
		}
		err = deps.PartitionRoleRepo.Create(ctx, role)
		s.Require().NoError(err)

		createRoleReq := &partitionv1.CreateAccessRoleRequest{}
		createRoleReq.SetAccessId(created.GetId())
		createRoleReq.SetPartitionRoleId(role.GetID())
		_, err = deps.AccessBusiness.CreateAccessRole(ctx, createRoleReq)
		s.Require().NoError(err)
	}

	listReq := &partitionv1.ListAccessRoleRequest{}
	listReq.SetAccessId(created.GetId())
	resp, err := deps.AccessBusiness.ListAccessRoles(ctx, listReq)
	s.Require().NoError(err)
	s.GreaterOrEqual(len(resp.GetData()), 2)
}

func (s *BusinessTestSuite) TestRemoveAccessRole() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("RAR")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.AccessBusiness.CreateAccess(ctx, s.newCreateAccessReq(partition.GetID(), profileID))
	s.Require().NoError(err)

	role := &models.PartitionRole{
		Name: "temp-role",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err = deps.PartitionRoleRepo.Create(ctx, role)
	s.Require().NoError(err)

	createRoleReq := &partitionv1.CreateAccessRoleRequest{}
	createRoleReq.SetAccessId(created.GetId())
	createRoleReq.SetPartitionRoleId(role.GetID())
	accessRole, err := deps.AccessBusiness.CreateAccessRole(ctx, createRoleReq)
	s.Require().NoError(err)

	removeReq := &partitionv1.RemoveAccessRoleRequest{}
	removeReq.SetId(accessRole.GetId())
	err = deps.AccessBusiness.RemoveAccessRole(ctx, removeReq)
	s.Require().NoError(err)

	listReq := &partitionv1.ListAccessRoleRequest{}
	listReq.SetAccessId(created.GetId())
	resp, err := deps.AccessBusiness.ListAccessRoles(ctx, listReq)
	s.Require().NoError(err)
	s.Empty(resp.GetData())
}

// ========================
// Page Business Tests
// ========================

func (s *BusinessTestSuite) TestCreatePage() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("CPg")
	partition := s.createTestPartition(tenant.GetID())
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	page, err := deps.PageBusiness.CreatePage(ctx, &partitionv1.CreatePageRequest{
		PartitionId: partition.GetID(),
		Name:        "login",
		Html:        "<h1>Login</h1>",
	})
	s.Require().NoError(err)
	s.Equal("login", page.Name)
}

func (s *BusinessTestSuite) TestCreatePage_InvalidPartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

	_, err := deps.PageBusiness.CreatePage(ctx, &partitionv1.CreatePageRequest{
		PartitionId: "nonexistent",
		Name:        "bad",
		Html:        "<h1>Bad</h1>",
	})
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestGetPage() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("GPg")
	partition := s.createTestPartition(tenant.GetID())

	page := &models.Page{
		Name: "consent",
		HTML: "<h1>Consent</h1>",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.PageRepo.Create(ctx, page)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	fetched, err := deps.PageBusiness.GetPage(ctx, s.newGetPageByPartitionAndName(partition.GetID(), "consent"))
	s.Require().NoError(err)
	s.Equal("consent", fetched.GetName())
}

func (s *BusinessTestSuite) TestGetPage_NotFound() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

	_, err := deps.PageBusiness.GetPage(ctx, s.newGetPageByPartitionAndName("nonexistent", "nonexistent"))
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestRemovePage() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("RPg")
	partition := s.createTestPartition(tenant.GetID())

	page := &models.Page{
		Name: "temp",
		HTML: "<h1>Temp</h1>",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.PageRepo.Create(ctx, page)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	removePageReq := &partitionv1.RemovePageRequest{}
	removePageReq.SetId(page.GetID())
	err = deps.PageBusiness.RemovePage(ctx, removePageReq)
	s.Require().NoError(err)

	_, err = deps.PageBusiness.GetPage(ctx, s.newGetPageByPartitionAndName(partition.GetID(), "temp"))
	s.Require().Error(err)
}

// ========================
// Service Account Business Tests
// ========================

func (s *BusinessTestSuite) TestCreateServiceAccount_Internal() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	result, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx,
		partition.GetID(),
		profileID,
		"test-sa",
		"internal",
		[]string{"service_profile"},
		nil, nil, nil,
	)
	s.Require().NoError(err)
	s.Require().NotNil(result)
	s.NotEmpty(result.ClientSecret)
	s.Equal("internal", result.ServiceAccount.Type)
	s.Equal(profileID, result.ServiceAccount.ProfileID)
	s.NotEmpty(result.ServiceAccount.ClientID)
	s.NotEmpty(result.Client.GetID())
}

func (s *BusinessTestSuite) TestCreateServiceAccount_External() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	result, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx,
		partition.GetID(),
		profileID,
		"ext-sa",
		"external",
		nil, nil, nil, nil,
	)
	s.Require().NoError(err)
	s.Equal("external", result.ServiceAccount.Type)
}

func (s *BusinessTestSuite) TestCreateServiceAccount_InvalidType() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	_, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx,
		partition.GetID(),
		util.IDString(),
		"bad-sa",
		"unknown",
		nil, nil, nil, nil,
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "invalid service account type")
}

func (s *BusinessTestSuite) TestCreateServiceAccount_InvalidPartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

	_, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx,
		"nonexistent-partition",
		util.IDString(),
		"sa",
		"internal",
		nil, nil, nil, nil,
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "target partition not found")
}

func (s *BusinessTestSuite) TestGetServiceAccount_ByID() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx, partition.GetID(), profileID, "get-sa", "internal",
		nil, nil, nil, nil,
	)
	s.Require().NoError(err)

	fetched, err := deps.ServiceAccountBusiness.GetServiceAccount(ctx, created.ServiceAccount.GetID(), "", "")
	s.Require().NoError(err)
	s.Equal(created.ServiceAccount.GetID(), fetched.GetID())
}

func (s *BusinessTestSuite) TestGetServiceAccount_ByClientID() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	created, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx, partition.GetID(), profileID, "get-sa-cid", "internal",
		nil, nil, nil, nil,
	)
	s.Require().NoError(err)

	fetched, err := deps.ServiceAccountBusiness.GetServiceAccount(ctx, "", created.ServiceAccount.ClientID, "")
	s.Require().NoError(err)
	s.Equal(created.ServiceAccount.ClientID, fetched.ClientID)
}

func (s *BusinessTestSuite) TestGetServiceAccountByClientID_Empty() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	ctx = s.WithAuthClaims(ctx, util.IDString(), util.IDString(), util.IDString())

	_, err := deps.ServiceAccountBusiness.GetServiceAccount(ctx, "", "", "")
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestListServiceAccounts() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	// Create two SAs
	_, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx, partition.GetID(), profileID, "sa-1", "internal",
		nil, nil, nil, nil,
	)
	s.Require().NoError(err)

	_, err = deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx, partition.GetID(), profileID, "sa-2", "external",
		nil, nil, nil, nil,
	)
	s.Require().NoError(err)

	accounts, err := deps.ServiceAccountBusiness.ListServiceAccounts(ctx, partition.GetID())
	s.Require().NoError(err)
	s.GreaterOrEqual(len(accounts), 2)
}

// ========================
// Remove Guards Tests
// ========================

func (s *BusinessTestSuite) TestRemoveTenant_Empty() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("EmptyTenant")
	ctx = s.WithAuthClaims(ctx, tenant.TenantID, tenant.PartitionID, util.IDString())

	err := deps.TenantBusiness.RemoveTenant(ctx, tenant.GetID())
	s.Require().NoError(err)
}

func (s *BusinessTestSuite) TestRemoveTenant_WithPartitions() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("BusyTenant")
	partition := s.createTestPartition(tenant.GetID())

	// Use the partition's tenant/partition scope so CountByTenantID can find the partition
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	err := deps.TenantBusiness.RemoveTenant(ctx, tenant.GetID())
	s.Require().Error(err)
	s.Contains(err.Error(), "partition(s) still exist")
}

func (s *BusinessTestSuite) TestRemovePartition_Empty() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	err := deps.PartitionBusiness.RemovePartition(ctx, partition.GetID())
	s.Require().NoError(err)
}

func (s *BusinessTestSuite) TestRemovePartition_WithAccess() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	access := &models.Access{
		ProfileID: util.IDString(),
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.AccessRepo.Create(ctx, access)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	err = deps.PartitionBusiness.RemovePartition(ctx, partition.GetID())
	s.Require().Error(err)
	s.Contains(err.Error(), "access record(s) still exist")
}

func (s *BusinessTestSuite) TestRemovePartition_WithClients() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	client := &models.Client{
		Name:     "test-client",
		ClientID: util.IDString(),
		Type:     "public",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.ClientRepo.Create(ctx, client)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	err = deps.PartitionBusiness.RemovePartition(ctx, partition.GetID())
	s.Require().Error(err)
	s.Contains(err.Error(), "client(s) still exist")
}

func (s *BusinessTestSuite) TestRemovePartition_WithServiceAccounts() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	sa := &models.ServiceAccount{
		ProfileID: util.IDString(),
		ClientID:  util.IDString(),
		Type:      "internal",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.ServiceAccountRepo.Create(ctx, sa)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	err = deps.PartitionBusiness.RemovePartition(ctx, partition.GetID())
	s.Require().Error(err)
	s.Contains(err.Error(), "service account(s) still exist")
}

// ========================
// Update Partition Role Tests
// ========================

func (s *BusinessTestSuite) TestUpdatePartitionRole() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	role := &models.PartitionRole{
		Name: "original",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.PartitionRoleRepo.Create(ctx, role)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	updated, err := deps.PartitionBusiness.UpdatePartitionRole(ctx, &partitionv1.UpdatePartitionRoleRequest{
		Id:   role.GetID(),
		Name: "renamed",
	})

	s.Require().NoError(err)
	s.Equal("renamed", updated.Name)
}

// ========================
// ListPage / UpdatePage Tests
// ========================

func (s *BusinessTestSuite) TestListPages() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	for _, name := range []string{"login", "consent"} {
		page := &models.Page{
			Name: name,
			HTML: "<h1>" + name + "</h1>",
			BaseModel: data.BaseModel{
				TenantID:    tenant.GetID(),
				PartitionID: partition.GetID(),
			},
		}
		err := deps.PageRepo.Create(ctx, page)
		s.Require().NoError(err)
	}

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	pages, err := deps.PageBusiness.ListPages(ctx, partition.GetID())
	s.Require().NoError(err)
	s.GreaterOrEqual(len(pages), 2)
}

func (s *BusinessTestSuite) TestUpdatePage() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	page := &models.Page{
		Name: "login",
		HTML: "<h1>Old</h1>",
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.PageRepo.Create(ctx, page)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	updated, err := deps.PageBusiness.UpdatePage(ctx, &partitionv1.UpdatePageRequest{
		Id:   page.GetID(),
		Html: "<h1>New</h1>",
	})

	s.Require().NoError(err)
	s.Equal("<h1>New</h1>", updated.Html)
}

// ========================
// ListAccess Tests
// ========================

func (s *BusinessTestSuite) TestListAccess_ByPartition() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	for range 2 {
		access := &models.Access{
			ProfileID: util.IDString(),
			BaseModel: data.BaseModel{
				TenantID:    tenant.GetID(),
				PartitionID: partition.GetID(),
			},
		}
		err := deps.AccessRepo.Create(ctx, access)
		s.Require().NoError(err)
	}

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	req := &partitionv1.ListAccessRequest{}
	req.SetPartitionId(partition.GetID())
	accesses, err := deps.AccessBusiness.ListAccess(ctx, req)
	s.Require().NoError(err)
	s.GreaterOrEqual(len(accesses), 2)
}

func (s *BusinessTestSuite) TestListAccess_ByProfile() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	access := &models.Access{
		ProfileID: profileID,
		BaseModel: data.BaseModel{
			TenantID:    tenant.GetID(),
			PartitionID: partition.GetID(),
		},
	}
	err := deps.AccessRepo.Create(ctx, access)
	s.Require().NoError(err)

	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), util.IDString())

	req := &partitionv1.ListAccessRequest{}
	req.SetProfileId(profileID)
	accesses, err := deps.AccessBusiness.ListAccess(ctx, req)
	s.Require().NoError(err)
	s.GreaterOrEqual(len(accesses), 1)
}

// ========================
// UpdateServiceAccount Tests
// ========================

func (s *BusinessTestSuite) TestUpdateServiceAccount() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	result, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx, partition.GetID(), profileID, "sa-update", "internal",
		[]string{"service_profile"}, nil, nil, nil,
	)
	s.Require().NoError(err)

	updated, err := deps.ServiceAccountBusiness.UpdateServiceAccount(ctx, &partitionv1.UpdateServiceAccountRequest{
		Id:        result.ServiceAccount.GetID(),
		Type:      "external",
		Audiences: []string{"service_tenancy", "service_notification"},
	})

	s.Require().NoError(err)
	s.Equal("external", updated.Type)
	s.Equal([]string{"service_tenancy", "service_notification"}, updated.Audiences)
}

// ========================
// Client Business Tests
// ========================

func (s *BusinessTestSuite) TestCreateClient() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	partition := s.setupTenantAndPartition()
	ctx = s.WithAuthClaims(ctx, partition.TenantID, partition.GetID(), util.IDString())

	result, err := deps.ClientBusiness.CreateClient(
		ctx, partition.GetID(), "test-client", "public",
		nil, nil, []string{"https://example.com/callback"},
		"", nil, nil, nil,
	)

	s.Require().NoError(err)
	s.NotNil(result.Client)
	s.Equal("public", result.Client.Type)
	s.NotEmpty(result.Client.ClientID)
}

func (s *BusinessTestSuite) TestUpdateClient() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	partition := s.setupTenantAndPartition()
	ctx = s.WithAuthClaims(ctx, partition.TenantID, partition.GetID(), util.IDString())

	result, err := deps.ClientBusiness.CreateClient(
		ctx, partition.GetID(), "original", "confidential",
		nil, nil, nil, "", nil, nil, nil,
	)
	s.Require().NoError(err)

	updated, err := deps.ClientBusiness.UpdateClient(ctx, &partitionv1.UpdateClientRequest{
		Id:           result.Client.GetID(),
		Name:         "updated",
		RedirectUris: []string{"https://new.example.com/callback"},
	})

	s.Require().NoError(err)
	s.Equal("updated", updated.Name)
	s.Equal([]string{"https://new.example.com/callback"}, updated.RedirectUris)
}

func (s *BusinessTestSuite) TestListClients() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	partition := s.setupTenantAndPartition()
	ctx = s.WithAuthClaims(ctx, partition.TenantID, partition.GetID(), util.IDString())

	for _, name := range []string{"client-a", "client-b"} {
		_, err := deps.ClientBusiness.CreateClient(
			ctx, partition.GetID(), name, "public",
			nil, nil, nil, "", nil, nil, nil,
		)
		s.Require().NoError(err)
	}

	clients, err := deps.ClientBusiness.ListClients(ctx, partition.GetID())
	s.Require().NoError(err)
	s.GreaterOrEqual(len(clients), 2)
}

func (s *BusinessTestSuite) TestRemoveClient() {
	ctx := s.SuiteCtx
	deps := s.SuiteDeps

	partition := s.setupTenantAndPartition()
	ctx = s.WithAuthClaims(ctx, partition.TenantID, partition.GetID(), util.IDString())

	result, err := deps.ClientBusiness.CreateClient(
		ctx, partition.GetID(), "rm-client", "public",
		nil, nil, nil, "", nil, nil, nil,
	)
	s.Require().NoError(err)

	err = deps.ClientBusiness.RemoveClient(ctx, result.Client.GetID())
	s.Require().NoError(err)

	_, err = deps.ClientBusiness.GetClient(ctx, result.Client.GetID())
	s.Require().Error(err)
}

func (s *BusinessTestSuite) TestRemoveServiceAccount() {
	ctx := s.SuiteCtx
	svc := s.SuiteSvc
	deps := s.SuiteDeps

	tenant := s.createTestTenant("T")
	partition := s.createTestPartition(tenant.GetID())

	profileID := util.IDString()
	s.SeedTenantAccess(ctx, svc, tenant.GetID(), partition.GetID(), profileID)
	ctx = s.WithAuthClaims(ctx, tenant.GetID(), partition.GetID(), profileID)

	result, err := deps.ServiceAccountBusiness.CreateServiceAccount(
		ctx, partition.GetID(), profileID, "sa-rm", "internal",
		nil, nil, nil, nil,
	)
	s.Require().NoError(err)

	err = deps.ServiceAccountBusiness.RemoveServiceAccount(ctx, result.ServiceAccount.GetID())
	s.Require().NoError(err)

	// Verify it's gone
	_, err = deps.ServiceAccountBusiness.GetServiceAccount(ctx, result.ServiceAccount.GetID(), "", "")
	s.Require().Error(err)
}
