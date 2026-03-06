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

type PartitionRoleRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (s *PartitionRoleRepositoryTestSuite) TestCreateAndGetByPartitionID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.PartitionRoleRepo

		partitionID := util.IDString()
		role := &models.PartitionRole{
			BaseModel: data.BaseModel{PartitionID: partitionID},
			Name:      "editor",
			IsDefault: false,
		}
		err := repo.Create(ctx, role)
		s.Require().NoError(err)
		s.NotEmpty(role.ID)

		roles, err := repo.GetByPartitionID(ctx, partitionID)
		s.Require().NoError(err)
		s.GreaterOrEqual(len(roles), 1)

		found := false
		for _, r := range roles {
			if r.ID == role.ID {
				s.Equal("editor", r.Name)
				found = true
			}
		}
		s.True(found)
	})
}

func (s *PartitionRoleRepositoryTestSuite) TestGetDefaultByPartitionID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.PartitionRoleRepo

		partitionID := util.IDString()

		// Create default and non-default roles
		defaultRole := &models.PartitionRole{
			BaseModel: data.BaseModel{PartitionID: partitionID},
			Name:      "member",
			IsDefault: true,
		}
		nonDefaultRole := &models.PartitionRole{
			BaseModel: data.BaseModel{PartitionID: partitionID},
			Name:      "admin",
			IsDefault: false,
		}
		s.Require().NoError(repo.Create(ctx, defaultRole))
		s.Require().NoError(repo.Create(ctx, nonDefaultRole))

		defaults, err := repo.GetDefaultByPartitionID(ctx, partitionID)
		s.Require().NoError(err)
		s.GreaterOrEqual(len(defaults), 1)

		for _, r := range defaults {
			s.True(r.IsDefault)
		}
	})
}

func (s *PartitionRoleRepositoryTestSuite) TestGetRolesByID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.PartitionRoleRepo

		r1 := &models.PartitionRole{Name: "r1"}
		r2 := &models.PartitionRole{Name: "r2"}
		s.Require().NoError(repo.Create(ctx, r1))
		s.Require().NoError(repo.Create(ctx, r2))

		roles, err := repo.GetRolesByID(ctx, r1.ID, r2.ID)
		s.Require().NoError(err)
		s.Len(roles, 2)
	})
}

func (s *PartitionRoleRepositoryTestSuite) TestGetByPartitionAndNames() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.PartitionRoleRepo

		partitionID := util.IDString()
		for _, name := range []string{"viewer", "editor", "admin"} {
			r := &models.PartitionRole{
				BaseModel: data.BaseModel{PartitionID: partitionID},
				Name:      name,
			}
			s.Require().NoError(repo.Create(ctx, r))
		}

		roles, err := repo.GetByPartitionAndNames(ctx, partitionID, []string{"viewer", "admin"})
		s.Require().NoError(err)
		s.Len(roles, 2)
	})
}

func (s *PartitionRoleRepositoryTestSuite) TestGetByPartitionID_Empty() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.PartitionRoleRepo

		roles, err := repo.GetByPartitionID(ctx, "nonexistent")
		s.Require().NoError(err)
		s.Empty(roles)
	})
}

func TestPartitionRoleRepository(t *testing.T) {
	suite.Run(t, new(PartitionRoleRepositoryTestSuite))
}
