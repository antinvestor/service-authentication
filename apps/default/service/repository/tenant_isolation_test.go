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

package repository_test

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/security"
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
	tests.BaseTestSuite
}

func TestTenantIsolationTestSuite(t *testing.T) {
	suite.Run(t, new(TenantIsolationTestSuite))
}

// tenantCtx builds a context carrying authentication claims for the given
// tenant/partition. It deliberately starts from the raw test context —
// the context returned by CreateService carries the skip-tenancy flag for
// fixture setup and would bypass RLS scoping.
func tenantCtx(t *testing.T, tenantID, partitionID string) context.Context {
	claims := &security.AuthenticationClaims{
		TenantID:    tenantID,
		PartitionID: partitionID,
		AccessID:    util.IDString(),
		SessionID:   util.IDString(),
	}
	claims.Subject = "user-" + tenantID
	return claims.ClaimsToContext(t.Context())
}

func (suite *TenantIsolationTestSuite) TestLogin_CrossTenantReadsReturnNothing() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		_, _, deps := suite.CreateService(t, dep)
		repo := deps.LoginRepo

		ctxA := tenantCtx(t, "tenant-iso-a", "partition-iso-a")
		ctxB := tenantCtx(t, "tenant-iso-b", "partition-iso-b")

		login := &models.Login{
			ProfileID: "profile-iso-a",
			Source:    string(models.LoginSourceDirect),
		}
		require.NoError(t, repo.Create(ctxA, login))
		require.NotEmpty(t, login.ID)
		require.Equal(t, "tenant-iso-a", login.TenantID,
			"row must be stamped with the creating tenant")

		// Tenant A sees its own row through the restricted role.
		own, err := repo.GetByProfileID(ctxA, login.ProfileID)
		require.NoError(t, err)
		require.Equal(t, login.ID, own.ID)

		// Tenant B must not see tenant A's login by any lookup path.
		_, err = repo.GetByProfileID(ctxB, login.ProfileID)
		require.Error(t, err, "cross-tenant GetByProfileID must not return tenant A's login")

		// A claim-less context keeps match-all semantics (system path).
		all, err := repo.GetByProfileID(t.Context(), login.ProfileID)
		require.NoError(t, err)
		assert.Equal(t, login.ID, all.ID)
	})
}

func (suite *TenantIsolationTestSuite) TestLoginEvent_CrossTenantReadsReturnNothing() {
	suite.WithTestDependancies(suite.T(), func(t *testing.T, dep *definition.DependencyOption) {
		_, _, deps := suite.CreateService(t, dep)
		repo := deps.LoginEventRepo

		ctxA := tenantCtx(t, "tenant-iso-a", "partition-iso-a")
		ctxB := tenantCtx(t, "tenant-iso-b", "partition-iso-b")

		event := &models.LoginEvent{
			ProfileID:        "profile-iso-a",
			LoginID:          util.IDString(),
			LoginChallengeID: "challenge-iso-a",
			ContactID:        util.IDString(),
			Status:           1,
		}
		require.NoError(t, repo.Create(ctxA, event))
		require.NotEmpty(t, event.ID)
		require.Equal(t, "tenant-iso-a", event.TenantID,
			"row must be stamped with the creating tenant")

		// Tenant A sees its own event through the restricted role.
		own, err := repo.GetByLoginChallenge(ctxA, event.LoginChallengeID)
		require.NoError(t, err)
		require.NotNil(t, own)
		require.Equal(t, event.ID, own.ID)

		// Tenant B must not see tenant A's event by any lookup path.
		crossChallenge, err := repo.GetByLoginChallenge(ctxB, event.LoginChallengeID)
		require.NoError(t, err)
		assert.Nil(t, crossChallenge, "cross-tenant GetByLoginChallenge must not return tenant A's event")

		crossRecent, err := repo.GetMostRecentByProfileID(ctxB, event.ProfileID)
		require.NoError(t, err)
		assert.Nil(t, crossRecent, "cross-tenant GetMostRecentByProfileID must not return tenant A's event")

		// A claim-less context keeps match-all semantics (system path).
		all, err := repo.GetByLoginChallenge(t.Context(), event.LoginChallengeID)
		require.NoError(t, err)
		require.NotNil(t, all)
		assert.Equal(t, event.ID, all.ID)
	})
}
