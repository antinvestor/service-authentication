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

package events_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/events"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/security"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
)

type SyncClientPersistTestSuite struct {
	tests.BaseTestSuite
}

func TestSyncClientPersistTestSuite(t *testing.T) {
	suite.Run(t, new(SyncClientPersistTestSuite))
}

func (s *SyncClientPersistTestSuite) SetupSuite() {
	s.BaseTestSuite.SetupSuite()
	s.CreateSuiteService()
}

// createClient stores a partition client; the sync handler runs on the
// system path, so the context skips tenancy checks just as Execute does.
func (s *SyncClientPersistTestSuite) createClient() *models.Client {
	ctx := security.SkipTenancyChecksOnClaims(s.SuiteCtx)
	tenantID, partitionID := util.IDString(), util.IDString()
	cl := &models.Client{
		Name:     "sync-persist",
		ClientID: util.IDString(),
		Type:     "public",
		BaseModel: data.BaseModel{
			TenantID:    tenantID,
			PartitionID: partitionID,
		},
	}
	s.Require().NoError(s.SuiteDeps.ClientRepo.Create(ctx, cl))
	return cl
}

func (s *SyncClientPersistTestSuite) TestUpdateClientWithResponse_PersistsHydraResponse() {
	ctx := security.SkipTenancyChecksOnClaims(s.SuiteCtx)
	repo := s.SuiteDeps.ClientRepo
	created := s.createClient()

	cl, err := repo.GetByID(ctx, created.GetID())
	s.Require().NoError(err)
	s.Require().Nil(cl.SyncedAt)

	err = events.UpdateClientWithResponse(ctx, repo, cl, []byte(`{"client_name":"synced","audience":["https://api.stawi.org/files"]}`))
	s.Require().NoError(err)

	stored, err := repo.GetByID(ctx, created.GetID())
	s.Require().NoError(err)
	s.NotNil(stored.SyncedAt, "synced_at must be persisted so the client is not re-synced forever")
	s.Equal("synced", stored.Properties["client_name"])
	s.Equal(created.Version+1, stored.Version)
}

func (s *SyncClientPersistTestSuite) TestUpdateClientWithResponse_StaleClientReturnsConflict() {
	ctx := security.SkipTenancyChecksOnClaims(s.SuiteCtx)
	repo := s.SuiteDeps.ClientRepo
	created := s.createClient()

	first, err := repo.GetByID(ctx, created.GetID())
	s.Require().NoError(err)
	stale, err := repo.GetByID(ctx, created.GetID())
	s.Require().NoError(err)

	s.Require().NoError(events.UpdateClientWithResponse(ctx, repo, first, []byte(`{"client_name":"first"}`)))

	err = events.UpdateClientWithResponse(ctx, repo, stale, []byte(`{"client_name":"stale"}`))
	s.Require().ErrorIs(err, repository.ErrUpdateConflict)

	stored, err := repo.GetByID(ctx, created.GetID())
	s.Require().NoError(err)
	s.Equal("first", stored.Properties["client_name"], "a stale sync must not overwrite a newer one")
}
