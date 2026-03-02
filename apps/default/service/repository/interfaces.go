package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/datastore"
)

// LoginRepository handles database operations for Login entities
type LoginRepository interface {
	datastore.BaseRepository[*models.Login]
	// GetByProfileID retrieves a login by profile id
	GetByProfileID(ctx context.Context, profileID string) (*models.Login, error)
}

// LoginEventRepository handles database operations for LoginEvent entities
type LoginEventRepository interface {
	datastore.BaseRepository[*models.LoginEvent]
	// GetByLoginChallenge retrieves a login event by the Hydra login challenge ID
	GetByLoginChallenge(ctx context.Context, loginChallengeID string) (*models.LoginEvent, error)
	// GetMostRecentByProfileID retrieves the most recent login event for a profile
	GetMostRecentByProfileID(ctx context.Context, profileID string) (*models.LoginEvent, error)
	// GetByOauth2SessionID retrieves the login event linked to a Hydra OAuth2 session
	GetByOauth2SessionID(ctx context.Context, oauth2SessionID string) (*models.LoginEvent, error)
}

// SessionRepository handles database operations for Session entities
type SessionRepository interface {
	datastore.BaseRepository[*models.Session]
	// GetByProfileID retrieves sessions for a profile
	GetByProfileID(ctx context.Context, profileID string) ([]*models.Session, error)
	// DeleteExpired removes expired sessions
	DeleteExpired(ctx context.Context) error
}
