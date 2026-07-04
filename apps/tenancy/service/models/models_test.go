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

package models

import (
	"testing"
	"time"

	commonv1 "buf.build/gen/go/antinvestor/common/protocolbuffers/go/common/v1"
	"github.com/antinvestor/service-authentication/pkg/partitionpolicy"
	"github.com/pitabwire/frame/v2/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type ModelsTestSuite struct {
	suite.Suite
}

func TestModelsTestSuite(t *testing.T) {
	suite.Run(t, new(ModelsTestSuite))
}

func (suite *ModelsTestSuite) TestTenant_ToAPI() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestTenant_ToAPI_EmptyProperties() {
	t := suite.T()
	tenant := &Tenant{
		BaseModel: data.BaseModel{ID: "t-2"},
		Name:      "Empty",
	}

	api := tenant.ToAPI()
	assert.Equal(t, "t-2", api.Id)
	assert.Equal(t, "Empty", api.Name)
}

func (suite *ModelsTestSuite) TestPartition_ToAPI() {
	t := suite.T()
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
	partition.SetAllowAutoAccess(false)

	api := partition.ToAPI()
	require.NotNil(t, api)
	assert.Equal(t, "part-1", api.Id)
	assert.Equal(t, "tenant-1", api.TenantId)
	assert.Equal(t, "parent-1", api.ParentId)
	assert.Equal(t, "Test Partition", api.Name)
	assert.Equal(t, commonv1.STATE_ACTIVE, api.State)
	assert.NotNil(t, api.Properties)
	assert.Equal(t, false, api.Properties.AsMap()[partitionpolicy.PropertyAllowAutoAccess])
}

func (suite *ModelsTestSuite) TestPartitionRole_ToAPI_Active() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestPartitionRole_ToAPI_Deleted() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestPage_ToAPI() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestAccess_ToAPI_Valid() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestAccess_ToAPI_NilPartition() {
	t := suite.T()
	access := &Access{
		BaseModel: data.BaseModel{ID: "access-2"},
		ProfileID: "profile-2",
	}

	api, err := access.ToAPI(nil)
	assert.Error(t, err)
	assert.Nil(t, api)
	assert.Contains(t, err.Error(), "no partition exists")
}

func (suite *ModelsTestSuite) TestAccessRole_ToAPI() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestAccessRole_ToAPI_NilRole() {
	t := suite.T()
	ar := &AccessRole{
		BaseModel: data.BaseModel{ID: "ar-2"},
		AccessID:  "access-1",
	}

	api := ar.ToAPI(nil)
	require.NotNil(t, api)
	assert.Equal(t, "ar-2", api.Id)
	assert.Nil(t, api.Role)
}

func (suite *ModelsTestSuite) TestPartition_ToAPI_WithDomain() {
	t := suite.T()
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

func (suite *ModelsTestSuite) TestPartition_ToAPI_NoDomain() {
	t := suite.T()
	partition := &Partition{
		BaseModel:  data.BaseModel{ID: "part-no-domain"},
		Properties: data.JSONMap{"key": "val"},
	}

	api := partition.ToAPI()
	assert.Empty(t, api.Domain)
}

func (suite *ModelsTestSuite) TestPartitionRole_ToAPI_WithIsDefault() {
	t := suite.T()
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
