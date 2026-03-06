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
	assert.Equal(t, "ar-1", api.Id)
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
	assert.Equal(t, "ar-2", api.Id)
	assert.Nil(t, api.Role)
}

// Client tests

func TestClient_ToAPI(t *testing.T) {
	client := &Client{
		BaseModel: data.BaseModel{
			ID:          "client-1",
			TenantID:    "tenant-1",
			PartitionID: "part-1",
			CreatedAt:   time.Now(),
		},
		Name:         "Test Client",
		ClientID:     "oauth-client-id",
		ClientSecret: "secret",
		Type:         "public",
		GrantTypes:   data.JSONMap{"grant_types": []any{"authorization_code"}},
		RedirectURIs: data.JSONMap{"uris": []any{"https://app.example.com/callback"}},
		Scopes:       "openid offline_access",
		Audiences:    data.JSONMap{"namespaces": []any{"service_profile"}},
		Roles:        data.JSONMap{"roles": []any{"admin", "member"}},
		Properties:   data.JSONMap{"custom": "value"},
	}

	api := client.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "client-1", api.Id)
	assert.Equal(t, "oauth-client-id", api.ClientId)
	assert.Equal(t, "public", api.Type)
	assert.Equal(t, "openid offline_access", api.Scopes)
	assert.Equal(t, []string{"authorization_code"}, api.GrantTypes)
	assert.Equal(t, []string{"https://app.example.com/callback"}, api.RedirectUris)
	assert.Equal(t, []string{"service_profile"}, api.Audiences)
	assert.Equal(t, []string{"admin", "member"}, api.Roles)
	assert.NotNil(t, api.Properties)
}

func TestClient_ToAPI_Deleted(t *testing.T) {
	client := &Client{
		BaseModel: data.BaseModel{
			ID:        "client-2",
			DeletedAt: gorm.DeletedAt{Time: time.Now(), Valid: true},
		},
		Name:     "Deleted Client",
		ClientID: "deleted-id",
		Type:     "internal",
	}

	api := client.ToAPI()
	assert.Equal(t, commonv1.STATE_DELETED, api.State)
}

func TestClient_ToAPI_NilOptionalFields(t *testing.T) {
	client := &Client{
		BaseModel: data.BaseModel{ID: "client-3"},
		Name:      "Minimal",
		ClientID:  "min-id",
		Type:      "public",
	}

	api := client.ToAPI()
	require.NotNil(t, api)
	assert.Empty(t, api.Audiences)
	assert.Nil(t, api.Properties)
}

func TestClient_GetRoleNames(t *testing.T) {
	tests := []struct {
		name     string
		roles    data.JSONMap
		expected []string
	}{
		{"nil roles", nil, nil},
		{"empty roles", data.JSONMap{}, nil},
		{"missing key", data.JSONMap{"other": "value"}, nil},
		{"[]any roles", data.JSONMap{"roles": []any{"admin", "member"}}, []string{"admin", "member"}},
		{"[]string roles", data.JSONMap{"roles": []string{"viewer"}}, []string{"viewer"}},
		{"mixed types in []any", data.JSONMap{"roles": []any{"admin", 123}}, []string{"admin"}},
		{"wrong type", data.JSONMap{"roles": "not-a-slice"}, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{Roles: tc.roles}
			result := client.GetRoleNames()
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ServiceAccount tests

func TestServiceAccount_ToAPI(t *testing.T) {
	sa := &ServiceAccount{
		BaseModel: data.BaseModel{
			ID:          "sa-1",
			TenantID:    "tenant-1",
			PartitionID: "part-1",
			CreatedAt:   time.Now(),
		},
		ProfileID:  "profile-1",
		ClientID:   "sa-client-id",
		ClientRef:  "client-ref-1",
		Type:       "internal",
		Audiences:  data.JSONMap{"namespaces": []any{"service_tenancy"}},
		Properties: data.JSONMap{"custom": "prop"},
	}

	api := sa.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "sa-1", api.Id)
	assert.Equal(t, "tenant-1", api.TenantId)
	assert.Equal(t, "part-1", api.PartitionId)
	assert.Equal(t, "profile-1", api.ProfileId)
	assert.Equal(t, "sa-client-id", api.ClientId)
	assert.Equal(t, "internal", api.Type)
	assert.Equal(t, []string{"service_tenancy"}, api.Audiences)
	assert.NotNil(t, api.Properties)
}

func TestServiceAccount_ToAPI_Deleted(t *testing.T) {
	sa := &ServiceAccount{
		BaseModel: data.BaseModel{
			ID:        "sa-2",
			DeletedAt: gorm.DeletedAt{Time: time.Now(), Valid: true},
		},
		ProfileID: "p-2",
		ClientID:  "sa-del",
		Type:      "external",
	}

	api := sa.ToAPI()
	assert.Equal(t, commonv1.STATE_DELETED, api.State)
	assert.Equal(t, "external", api.Type)
}

func TestServiceAccount_ToAPI_NilProperties(t *testing.T) {
	sa := &ServiceAccount{
		BaseModel: data.BaseModel{ID: "sa-3"},
		ProfileID: "p-3",
		ClientID:  "sa-min",
		Type:      "internal",
	}

	api := sa.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "internal", api.Type)
	assert.Nil(t, api.Properties)
	assert.Nil(t, api.Audiences)
}

func TestPartition_ToAPI_WithDomain(t *testing.T) {
	partition := &Partition{
		BaseModel: data.BaseModel{
			ID:       "part-domain",
			TenantID: "t-1",
		},
		Name:       "Domain Partition",
		Domain:     "example.com",
		Properties: data.JSONMap{"key": "val"},
	}

	api := partition.ToAPI()
	require.NotNil(t, api)
	// Domain should be a first-class field
	assert.Equal(t, "example.com", api.Domain)
	props := api.Properties.AsMap()
	assert.Equal(t, "val", props["key"])
}

func TestPartition_ToAPI_NoDomain(t *testing.T) {
	partition := &Partition{
		BaseModel:  data.BaseModel{ID: "part-no-domain"},
		Properties: data.JSONMap{"key": "val"},
	}

	api := partition.ToAPI()
	assert.Empty(t, api.Domain)
}

func TestPartitionRole_ToAPI_WithIsDefault(t *testing.T) {
	role := &PartitionRole{
		BaseModel:  data.BaseModel{ID: "role-def", PartitionID: "p-1"},
		Name:       "default-role",
		IsDefault:  true,
		Properties: data.JSONMap{},
	}

	api := role.ToAPI()
	props := api.Properties.AsMap()
	assert.Equal(t, true, props["is_default"])
}

func TestClient_ToServiceAccountAPI(t *testing.T) {
	client := &Client{
		BaseModel: data.BaseModel{
			ID:          "client-sa-1",
			TenantID:    "tenant-1",
			PartitionID: "part-1",
			CreatedAt:   time.Now(),
		},
		Name:         "SA Client",
		ClientID:     "sa-oauth-id",
		Type:         "internal",
		GrantTypes:   data.JSONMap{"grant_types": []any{"client_credentials"}},
		RedirectURIs: data.JSONMap{"uris": []any{"https://example.com"}},
		Roles:        data.JSONMap{"roles": []any{"admin"}},
		Audiences:    data.JSONMap{"namespaces": []any{"service_profile"}},
		Properties:   data.JSONMap{"custom": "val"},
	}

	api := client.ToServiceAccountAPI()
	require.NotNil(t, api)
	assert.Equal(t, "client-sa-1", api.Id)
	assert.Equal(t, "tenant-1", api.TenantId)
	assert.Equal(t, "part-1", api.PartitionId)
	assert.Equal(t, "sa-oauth-id", api.ClientId)
	assert.Equal(t, "internal", api.Type)
	assert.Equal(t, []string{"service_profile"}, api.Audiences)
	assert.NotNil(t, api.Properties)
	props := api.Properties.AsMap()
	assert.Equal(t, "internal", props["type"])
}

func TestClient_ToServiceAccountAPI_Deleted(t *testing.T) {
	client := &Client{
		BaseModel: data.BaseModel{
			ID:        "client-sa-2",
			DeletedAt: gorm.DeletedAt{Time: time.Now(), Valid: true},
		},
		ClientID: "sa-del",
		Type:     "external",
	}

	api := client.ToServiceAccountAPI()
	assert.Equal(t, commonv1.STATE_DELETED, api.State)
	assert.Equal(t, "external", api.Type)
}

func TestJsonMapToStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		m        data.JSONMap
		key      string
		expected []string
	}{
		{"nil map", nil, "key", nil},
		{"missing key", data.JSONMap{"other": "val"}, "key", nil},
		{"[]any strings", data.JSONMap{"k": []any{"a", "b"}}, "k", []string{"a", "b"}},
		{"[]string", data.JSONMap{"k": []string{"x", "y"}}, "k", []string{"x", "y"}},
		{"[]any mixed types", data.JSONMap{"k": []any{"a", 123, "b"}}, "k", []string{"a", "b"}},
		{"wrong type", data.JSONMap{"k": 42}, "k", nil},
		{"empty []any", data.JSONMap{"k": []any{}}, "k", []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := jsonMapToStringSlice(tc.m, tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}
