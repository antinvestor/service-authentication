package repository_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/tests"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/util"
	"github.com/stretchr/testify/suite"
)

type LoginEventRepositoryTestSuite struct {
	tests.BaseTestSuite
}

func (s *LoginEventRepositoryTestSuite) TestSaveAndGetByID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		event := &models.LoginEvent{
			BaseModel:        data.BaseModel{ID: util.IDString()},
			ClientID:         "client-1",
			LoginChallengeID: "challenge-1",
			ProfileID:        "profile-1",
			ContactID:        "contact-1",
			IP:               "127.0.0.1",
			Status:           1,
		}

		err := repo.Create(ctx, event)
		s.Require().NoError(err)

		found, err := repo.GetByID(ctx, event.ID)
		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal("client-1", found.ClientID)
		s.Equal("challenge-1", found.LoginChallengeID)
		s.Equal("profile-1", found.ProfileID)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetByID_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		found, err := repo.GetByID(ctx, "nonexistent")
		s.NoError(err)
		s.Nil(found)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetByLoginChallenge() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		challengeID := "challenge-" + util.IDString()
		event := &models.LoginEvent{
			BaseModel:        data.BaseModel{ID: util.IDString()},
			LoginChallengeID: challengeID,
			ClientID:         "client-2",
		}

		err := repo.Create(ctx, event)
		s.Require().NoError(err)

		found, err := repo.GetByLoginChallenge(ctx, challengeID)
		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal(event.ID, found.ID)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetByLoginChallenge_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		found, err := repo.GetByLoginChallenge(ctx, "nonexistent")
		s.NoError(err)
		s.Nil(found)
	})
}

func (s *LoginEventRepositoryTestSuite) TestDelete() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		event := &models.LoginEvent{
			BaseModel: data.BaseModel{ID: util.IDString()},
			ClientID:  "client-del",
		}

		err := repo.Create(ctx, event)
		s.Require().NoError(err)

		err = repo.Delete(ctx, event.ID)
		s.Require().NoError(err)

		// Soft delete - GetByID from base should still not find it
		found, err := repo.GetByID(ctx, event.ID)
		s.NoError(err)
		s.Nil(found)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetMostRecentByProfileID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		profileID := "profile-" + util.IDString()

		event1 := &models.LoginEvent{
			BaseModel: data.BaseModel{ID: util.IDString()},
			ProfileID: profileID,
			ClientID:  "client-old",
		}
		err := repo.Create(ctx, event1)
		s.Require().NoError(err)

		event2 := &models.LoginEvent{
			BaseModel: data.BaseModel{ID: util.IDString()},
			ProfileID: profileID,
			ClientID:  "client-new",
		}
		err = repo.Create(ctx, event2)
		s.Require().NoError(err)

		found, err := repo.GetMostRecentByProfileID(ctx, profileID)
		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal(profileID, found.ProfileID)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetMostRecentByProfileID_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		found, err := repo.GetMostRecentByProfileID(ctx, "nonexistent")
		s.NoError(err)
		s.Nil(found)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetByOauth2SessionID() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		sessionID := "oauth2-session-" + util.IDString()
		event := &models.LoginEvent{
			BaseModel:       data.BaseModel{ID: util.IDString()},
			Oauth2SessionID: sessionID,
			ClientID:        "client-oauth2",
		}

		err := repo.Create(ctx, event)
		s.Require().NoError(err)

		found, err := repo.GetByOauth2SessionID(ctx, sessionID)
		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal(event.ID, found.ID)
	})
}

func (s *LoginEventRepositoryTestSuite) TestGetByOauth2SessionID_NotFound() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		found, err := repo.GetByOauth2SessionID(ctx, "nonexistent")
		s.NoError(err)
		s.Nil(found)
	})
}

func (s *LoginEventRepositoryTestSuite) TestUpdateFields() {
	s.WithTestDependancies(s.T(), func(t *testing.T, dep *definition.DependencyOption) {
		ctx, _, deps := s.CreateService(t, dep)
		repo := deps.LoginEventRepo

		event := &models.LoginEvent{
			BaseModel: data.BaseModel{ID: util.IDString()},
			ClientID:  "client-upd",
			ProfileID: "original-profile",
		}

		err := repo.Create(ctx, event)
		s.Require().NoError(err)

		event.ProfileID = "updated-profile"
		event.VerificationID = "verification-1"
		_, err = repo.Update(ctx, event, "profile_id", "verification_id")
		s.Require().NoError(err)

		found, err := repo.GetByID(ctx, event.ID)
		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal("updated-profile", found.ProfileID)
		s.Equal("verification-1", found.VerificationID)
	})
}

func TestLoginEventRepository(t *testing.T) {
	suite.Run(t, new(LoginEventRepositoryTestSuite))
}
