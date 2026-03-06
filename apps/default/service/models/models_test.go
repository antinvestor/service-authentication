package models

import (
	"testing"
	"time"

	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/suite"
)

type ModelsTestSuite struct {
	suite.Suite
}

func (s *ModelsTestSuite) TestLoginSourceConstants() {
	s.Equal(LoginSource("direct"), LoginSourceDirect)
	s.Equal(LoginSource("google"), LoginSourceGoogle)
	s.Equal(LoginSource("facebook"), LoginSourceMeta)
}

func (s *ModelsTestSuite) TestLoginEvent_Getters() {
	le := LoginEvent{
		BaseModel: data.BaseModel{
			ID:          "event-1",
			TenantID:    "tenant-1",
			PartitionID: "part-1",
		},
		ProfileID: "profile-1",
		AccessID:  "access-1",
		ContactID: "contact-1",
		SessionID: "session-1",
		DeviceID:  "device-1",
	}

	s.Equal("tenant-1", le.GetTenantID())
	s.Equal("part-1", le.GetPartitionID())
	s.Equal("profile-1", le.GetProfileID())
	s.Equal("access-1", le.GetAccessID())
	s.Equal("contact-1", le.GetContactID())
	s.Equal("session-1", le.GetSessionID())
	s.Equal("device-1", le.GetDeviceID())
}

func (s *ModelsTestSuite) TestLoginEvent_GetRoles_ReturnsEmpty() {
	le := LoginEvent{}
	roles := le.GetRoles()
	s.NotNil(roles)
	s.Empty(roles)
}

func (s *ModelsTestSuite) TestLoginEvent_EmptyGetters() {
	le := LoginEvent{}
	s.Empty(le.GetTenantID())
	s.Empty(le.GetPartitionID())
	s.Empty(le.GetProfileID())
	s.Empty(le.GetAccessID())
	s.Empty(le.GetContactID())
	s.Empty(le.GetSessionID())
	s.Empty(le.GetDeviceID())
}

func (s *ModelsTestSuite) TestLogin_Fields() {
	login := Login{
		BaseModel: data.BaseModel{ID: "login-1"},
		ProfileID: "profile-1",
		ClientID:  "client-1",
		Source:    "direct",
		Locked:    time.Now(),
	}

	s.Equal("login-1", login.ID)
	s.Equal("profile-1", login.ProfileID)
	s.Equal("client-1", login.ClientID)
	s.Equal("direct", login.Source)
	s.False(login.Locked.IsZero())
}

func (s *ModelsTestSuite) TestSession_Fields() {
	now := time.Now()
	session := Session{
		BaseModel:    data.BaseModel{ID: "session-1"},
		LoginEventID: "event-1",
		ExpiresAt:    now.Add(time.Hour),
		IssuedAt:     now,
		ProfileID:    "profile-1",
	}

	s.Equal("session-1", session.ID)
	s.Equal("event-1", session.LoginEventID)
	s.Equal("profile-1", session.ProfileID)
	s.True(session.ExpiresAt.After(now))
}

func TestModels(t *testing.T) {
	suite.Run(t, new(ModelsTestSuite))
}
