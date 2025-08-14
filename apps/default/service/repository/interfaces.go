package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
)

// LoginRepository handles database operations for Login entities
type LoginRepository interface {
	GetByID(ctx context.Context, id string) (*models.Login, error)
	// GetByProfileID retrieves a login by profile id
	GetByProfileID(ctx context.Context, profileID string) (*models.Login, error)
	// Save creates or updates a login record
	Save(ctx context.Context, login *models.Login) error
	// Delete removes a login record by ID
	Delete(ctx context.Context, id string) error
}

// APIKeyRepository handles database operations for APIKey entities
type APIKeyRepository interface {
	// GetByID retrieves an API key by ID
	GetByID(ctx context.Context, id string) (*models.APIKey, error)
	// GetByIDAndProfile retrieves an API key by ID and profile ID
	GetByIDAndProfile(ctx context.Context, id, profileID string) (*models.APIKey, error)
	// GetByKey retrieves an API key by key value
	GetByKey(ctx context.Context, key string) (*models.APIKey, error)
	// GetByProfileID retrieves all API keys for a profile
	GetByProfileID(ctx context.Context, profileID string) ([]*models.APIKey, error)
	// Save creates or updates an API key record
	Save(ctx context.Context, apiKey *models.APIKey) error
	// Delete removes an API key record by ID and profile ID
	Delete(ctx context.Context, id, profileID string) error
}

// LoginEventRepository handles database operations for LoginEvent entities
type LoginEventRepository interface {
	// GetByID retrieves a login event by ID
	GetByID(ctx context.Context, id string) (*models.LoginEvent, error)
	// Save creates or updates a login event record
	Save(ctx context.Context, loginEvent *models.LoginEvent) error
	// Delete removes a login event record by ID
	Delete(ctx context.Context, id string) error
}

// SessionRepository handles database operations for Session entities
type SessionRepository interface {
	// GetByID retrieves a session by ID
	GetByID(ctx context.Context, id string) (*models.Session, error)
	// GetByProfileID retrieves sessions for a profile
	GetByProfileID(ctx context.Context, profileID string) ([]*models.Session, error)
	// Save creates or updates a session record
	Save(ctx context.Context, session *models.Session) error
	// Delete removes a session record by ID
	Delete(ctx context.Context, id string) error
	// DeleteExpired removes expired sessions
	DeleteExpired(ctx context.Context) error
}
