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
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// TenantIsolationTestSuite exercises Postgres row level security across
// tenants. The base suite wires frametests/rlstest so application queries
// run as a non-superuser role — without that, the testcontainer superuser
// bypasses FORCE ROW LEVEL SECURITY and these assertions would pass
// vacuously even if the policies were broken.
type TenantIsolationTestSuite struct {
	BaseTestSuite
}

func TestTenantIsolationTestSuite(t *testing.T) {
	suite.Run(t, new(TenantIsolationTestSuite))
}

func (suite *TenantIsolationTestSuite) TestPartition_CrossTenantReadsReturnNothing() {
	t := suite.T()
	ctx, _, deps := suite.CreateService(t, definition.NewDependancyOption("partition_isolation", util.RandomAlphaNumericString(8), nil))
	repo := deps.PartitionRepo

	ctxA := suite.WithAuthClaims(ctx, "tenant-iso-a", "partition-iso-a", "profile-a")
	ctxB := suite.WithAuthClaims(ctx, "tenant-iso-b", "partition-iso-b", "profile-b")

	partition := &models.Partition{
		Name:        "tenant-a-private-partition",
		Description: "visible to tenant A only",
		State:       1,
	}
	partition.GenID(ctxA)
	require.NoError(t, repo.Create(ctxA, partition))
	require.Equal(t, "tenant-iso-a", partition.TenantID,
		"row must be stamped with the creating tenant")

	// Tenant A sees its own partition through the restricted role.
	own, err := repo.GetByID(ctxA, partition.GetID())
	require.NoError(t, err)
	require.Equal(t, partition.GetID(), own.GetID())

	// Tenant B must not see tenant A's partition by any lookup path.
	_, err = repo.GetByID(ctxB, partition.GetID())
	require.Error(t, err, "cross-tenant GetByID must not return tenant A's partition")

	count, err := repo.CountByTenantID(ctxB, "tenant-iso-a")
	require.NoError(t, err)
	assert.Zero(t, count, "cross-tenant count must not include tenant A's partitions")

	// A claim-less context keeps match-all semantics (system path).
	all, err := repo.GetByID(ctx, partition.GetID())
	require.NoError(t, err)
	assert.Equal(t, partition.GetID(), all.GetID())
}

func (suite *TenantIsolationTestSuite) TestAccess_CrossTenantReadsReturnNothing() {
	t := suite.T()
	ctx, _, deps := suite.CreateService(t, definition.NewDependancyOption("access_isolation", util.RandomAlphaNumericString(8), nil))
	accessRepo := deps.AccessRepo

	ctxA := suite.WithAuthClaims(ctx, "tenant-iso-a", "partition-iso-a", "profile-a")
	ctxB := suite.WithAuthClaims(ctx, "tenant-iso-b", "partition-iso-b", "profile-b")

	access := &models.Access{
		ProfileID: "profile-iso-a",
		State:     1,
	}
	access.GenID(ctxA)
	require.NoError(t, accessRepo.Create(ctxA, access))
	require.Equal(t, "tenant-iso-a", access.TenantID,
		"row must be stamped with the creating tenant")
	require.Equal(t, "partition-iso-a", access.PartitionID,
		"row must be stamped with the creating partition")

	// Tenant A sees its own access through the restricted role.
	own, err := accessRepo.GetByPartitionAndProfile(ctxA, access.PartitionID, access.ProfileID)
	require.NoError(t, err)
	require.Equal(t, access.GetID(), own.GetID())

	// Tenant B must not see tenant A's access by any lookup path.
	_, err = accessRepo.GetByPartitionAndProfile(ctxB, access.PartitionID, access.ProfileID)
	require.Error(t, err, "cross-tenant GetByPartitionAndProfile must not return tenant A's access")

	crossList, err := accessRepo.ListByProfileID(ctxB, access.ProfileID)
	require.NoError(t, err)
	assert.Empty(t, crossList, "cross-tenant list must not contain tenant A's access records")

	// A claim-less context keeps match-all semantics (system path).
	allList, err := accessRepo.ListByProfileID(ctx, access.ProfileID)
	require.NoError(t, err)
	assert.Len(t, allList, 1)
}
