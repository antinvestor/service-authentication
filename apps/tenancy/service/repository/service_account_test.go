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

type ServiceAccountRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (s *ServiceAccountRepositoryTestSuite) TestCreateAndGetByID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		partitionID := util.IDString()
		clientID := "sa-client-" + util.IDString()
		sa := &models.ServiceAccount{
			BaseModel: data.BaseModel{PartitionID: partitionID},
			ProfileID: "profile-1",
			ClientID:  clientID,
			Type:      "internal",
		}

		err := repo.Create(ctx, sa)
		s.Require().NoError(err)
		s.NotEmpty(sa.ID)

		found, err := repo.GetByID(ctx, sa.ID)
		s.Require().NoError(err)
		s.Equal("profile-1", found.ProfileID)
		s.Equal(clientID, found.ClientID)
		s.Equal("internal", found.Type)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestGetByClientID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		clientID := "unique-sa-" + util.IDString()
		sa := &models.ServiceAccount{
			ProfileID: "p-1",
			ClientID:  clientID,
			Type:      "external",
		}
		err := repo.Create(ctx, sa)
		s.Require().NoError(err)

		found, err := repo.GetByClientID(ctx, clientID)
		s.Require().NoError(err)
		s.Equal(sa.ID, found.ID)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestGetByClientID_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		_, err := repo.GetByClientID(ctx, "nonexistent")
		s.Error(err)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestGetByPartitionAndProfile() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		partitionID := util.IDString()
		profileID := "profile-" + util.IDString()
		sa := &models.ServiceAccount{
			BaseModel: data.BaseModel{PartitionID: partitionID},
			ProfileID: profileID,
			ClientID:  "c-" + util.IDString(),
			Type:      "internal",
		}
		err := repo.Create(ctx, sa)
		s.Require().NoError(err)

		found, err := repo.GetByPartitionAndProfile(ctx, partitionID, profileID)
		s.Require().NoError(err)
		s.Equal(sa.ID, found.ID)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestGetByClientAndProfile() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		clientID := "cp-" + util.IDString()
		profileID := "pp-" + util.IDString()
		sa := &models.ServiceAccount{
			ProfileID: profileID,
			ClientID:  clientID,
			Type:      "external",
		}
		err := repo.Create(ctx, sa)
		s.Require().NoError(err)

		found, err := repo.GetByClientAndProfile(ctx, clientID, profileID)
		s.Require().NoError(err)
		s.Equal(sa.ID, found.ID)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestGetByClientRef() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		clientRef := "ref-" + util.IDString()
		sa := &models.ServiceAccount{
			ProfileID: "p-ref",
			ClientID:  "c-" + util.IDString(),
			ClientRef: clientRef,
			Type:      "internal",
		}
		err := repo.Create(ctx, sa)
		s.Require().NoError(err)

		found, err := repo.GetByClientRef(ctx, clientRef)
		s.Require().NoError(err)
		s.Equal(sa.ID, found.ID)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestListByPartition() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		partitionID := util.IDString()
		for i := range 2 {
			sa := &models.ServiceAccount{
				BaseModel: data.BaseModel{PartitionID: partitionID},
				ProfileID: "p-" + util.IDString(),
				ClientID:  "c-" + util.IDString(),
				Type:      "internal",
			}
			err := repo.Create(ctx, sa)
			s.Require().NoError(err, "failed creating SA %d", i)
		}

		accounts, err := repo.ListByPartition(ctx, partitionID)
		s.Require().NoError(err)
		s.GreaterOrEqual(len(accounts), 2)
	})
}

func (s *ServiceAccountRepositoryTestSuite) TestListByPartition_Empty() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.Server.ServiceAccountRepo

		accounts, err := repo.ListByPartition(ctx, "empty-partition")
		s.Require().NoError(err)
		s.Empty(accounts)
	})
}

func TestServiceAccountRepository(t *testing.T) {
	suite.Run(t, new(ServiceAccountRepositoryTestSuite))
}
