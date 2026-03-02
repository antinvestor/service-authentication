package models

import (
	"testing"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestTenant_ToAPI(t *testing.T) {
	now := time.Now()
	tenant := &Tenant{
		BaseModel: data.BaseModel{
			ID:        "tenant-1",
			CreatedAt: now,
		},
		Name:        "Test Tenant",
		Description: "A test tenant",
		Properties:  data.JSONMap{"key": "value"},
	}

	api := tenant.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "tenant-1", api.Id)
	assert.Equal(t, "Test Tenant", api.Name)
	assert.Equal(t, "A test tenant", api.Description)
	assert.NotNil(t, api.Properties)
	assert.NotNil(t, api.CreatedAt)
}

func TestTenant_ToAPI_EmptyProperties(t *testing.T) {
	tenant := &Tenant{
		BaseModel: data.BaseModel{ID: "t-2"},
		Name:      "Empty",
	}

	api := tenant.ToAPI()
	assert.Equal(t, "t-2", api.Id)
	assert.Equal(t, "Empty", api.Name)
}

func TestPartition_ToAPI(t *testing.T) {
	now := time.Now()
	partition := &Partition{
		BaseModel: data.BaseModel{
			ID:        "part-1",
			TenantID:  "tenant-1",
			CreatedAt: now,
		},
		Name:        "Test Partition",
		Description: "A test partition",
		ParentID:    "parent-1",
		Properties:  data.JSONMap{"scope": "openid"},
		State:       int32(commonv1.STATE_ACTIVE),
	}

	api := partition.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "part-1", api.Id)
	assert.Equal(t, "tenant-1", api.TenantId)
	assert.Equal(t, "parent-1", api.ParentId)
	assert.Equal(t, "Test Partition", api.Name)
	assert.Equal(t, commonv1.STATE_ACTIVE, api.State)
	assert.NotNil(t, api.Properties)
}

func TestPartitionRole_ToAPI_Active(t *testing.T) {
	role := &PartitionRole{
		BaseModel: data.BaseModel{
			ID:          "role-1",
			PartitionID: "part-1",
			CreatedAt:   time.Now(),
		},
		Name:       "admin",
		Properties: data.JSONMap{},
	}

	api := role.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "role-1", api.Id)
	assert.Equal(t, "part-1", api.PartitionId)
	assert.Equal(t, "admin", api.Name)
	assert.Equal(t, commonv1.STATE_ACTIVE, api.State)
}

func TestPartitionRole_ToAPI_Deleted(t *testing.T) {
	role := &PartitionRole{
		BaseModel: data.BaseModel{
			ID:        "role-2",
			DeletedAt: gorm.DeletedAt{Time: time.Now(), Valid: true},
		},
		Name: "deleted-role",
	}

	api := role.ToAPI()
	assert.Equal(t, commonv1.STATE_DELETED, api.State)
}

func TestPage_ToAPI(t *testing.T) {
	page := &Page{
		BaseModel: data.BaseModel{
			ID:        "page-1",
			CreatedAt: time.Now(),
		},
		Name:       "login",
		HTML:       "<h1>Login</h1>",
		State:      int32(commonv1.STATE_ACTIVE),
		Properties: data.JSONMap{"theme": "dark"},
	}

	api := page.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "page-1", api.Id)
	assert.Equal(t, "login", api.Name)
	assert.Equal(t, "<h1>Login</h1>", api.Html)
	assert.Equal(t, commonv1.STATE_ACTIVE, api.State)
	assert.NotNil(t, api.Properties)
}

func TestAccess_ToAPI_Valid(t *testing.T) {
	access := &Access{
		BaseModel: data.BaseModel{
			ID:        "access-1",
			CreatedAt: time.Now(),
		},
		ProfileID: "profile-1",
		State:     int32(commonv1.STATE_ACTIVE),
	}

	partitionObj := &Partition{
		BaseModel: data.BaseModel{ID: "part-1", TenantID: "t-1"},
		Name:      "Test",
	}

	api, err := access.ToAPI(partitionObj.ToAPI())
	require.NoError(t, err)
	require.NotNil(t, api)
	assert.Equal(t, "access-1", api.Id)
	assert.Equal(t, "profile-1", api.ProfileId)
	assert.NotNil(t, api.Partition)
	assert.Equal(t, commonv1.STATE_ACTIVE, api.State)
}

func TestAccess_ToAPI_NilPartition(t *testing.T) {
	access := &Access{
		BaseModel: data.BaseModel{ID: "access-2"},
		ProfileID: "profile-2",
	}

	api, err := access.ToAPI(nil)
	assert.Error(t, err)
	assert.Nil(t, api)
	assert.Contains(t, err.Error(), "no partition exists")
}

func TestAccessRole_ToAPI(t *testing.T) {
	ar := &AccessRole{
		BaseModel:       data.BaseModel{ID: "ar-1"},
		AccessID:        "access-1",
		PartitionRoleID: "role-1",
	}

	roleObj := &PartitionRole{
		BaseModel: data.BaseModel{ID: "role-1", PartitionID: "part-1"},
		Name:      "admin",
	}

	api := ar.ToAPI(roleObj.ToAPI())
	require.NotNil(t, api)
	assert.Equal(t, "ar-1", api.AccessRoleId)
	assert.Equal(t, "access-1", api.AccessId)
	assert.NotNil(t, api.Role)
	assert.Equal(t, "admin", api.Role.Name)
}

func TestAccessRole_ToAPI_NilRole(t *testing.T) {
	ar := &AccessRole{
		BaseModel: data.BaseModel{ID: "ar-2"},
		AccessID:  "access-1",
	}

	api := ar.ToAPI(nil)
	require.NotNil(t, api)
	assert.Equal(t, "ar-2", api.AccessRoleId)
	assert.Nil(t, api.Role)
}
