package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/tests"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
)

type ClientRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (s *ClientRepositoryTestSuite) TestCreateAndGetByID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		tenant := &models.Tenant{Name: "T"}
		err := deps.TenantRepo.Create(ctx, tenant)
		s.Require().NoError(err)

		partitionID := util.IDString()
		partition := &models.Partition{
			Name: "P",
			BaseModel: data.BaseModel{
				ID: partitionID, TenantID: tenant.ID, PartitionID: partitionID,
			},
		}
		err = deps.PartitionRepo.Create(ctx, partition)
		s.Require().NoError(err)

		clientID := "oauth-" + util.IDString()
		client := &models.Client{
			BaseModel: data.BaseModel{
				TenantID:    tenant.ID,
				PartitionID: partitionID,
			},
			Name:     "Test Client",
			ClientID: clientID,
			Type:     "public",
			Scopes:   "openid offline_access",
		}
		err = repo.Create(ctx, client)
		s.Require().NoError(err)
		s.NotEmpty(client.ID)

		found, err := repo.GetByID(ctx, client.ID)
		s.Require().NoError(err)
		s.Equal("Test Client", found.Name)
		s.Equal(clientID, found.ClientID)
	})
}

func (s *ClientRepositoryTestSuite) TestGetByClientID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		clientID := "unique-" + util.IDString()
		client := &models.Client{
			Name:     "By ClientID",
			ClientID: clientID,
			Type:     "internal",
		}
		err := repo.Create(ctx, client)
		s.Require().NoError(err)

		found, err := repo.GetByClientID(ctx, clientID)
		s.Require().NoError(err)
		s.Equal(client.ID, found.ID)
	})
}

func (s *ClientRepositoryTestSuite) TestGetByClientID_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		_, err := repo.GetByClientID(ctx, "nonexistent")
		s.Error(err)
	})
}

func (s *ClientRepositoryTestSuite) TestListByPartition() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		partitionID := util.IDString()
		for i := range 3 {
			client := &models.Client{
				BaseModel: data.BaseModel{PartitionID: partitionID},
				Name:      "Client",
				ClientID:  util.IDString(),
				Type:      "public",
			}
			err := repo.Create(ctx, client)
			s.Require().NoError(err, "failed creating client %d", i)
		}

		clients, err := repo.ListByPartition(ctx, partitionID)
		s.Require().NoError(err)
		s.GreaterOrEqual(len(clients), 3)
	})
}

func (s *ClientRepositoryTestSuite) TestListByPartition_Empty() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ClientRepo

		clients, err := repo.ListByPartition(ctx, "empty-partition")
		s.Require().NoError(err)
		s.Empty(clients)
	})
}

func TestClientRepository(t *testing.T) {
	suite.Run(t, new(ClientRepositoryTestSuite))
}
