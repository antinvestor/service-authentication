package repository

import (
	"context"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
)

type sessionRepository struct {
	service *frame.Service
}

// NewSessionRepository creates a new instance of SessionRepository
func NewSessionRepository(service *frame.Service) SessionRepository {
	return &sessionRepository{
		service: service,
	}
}

// GetByID retrieves a session by ID
func (r *sessionRepository) GetByID(ctx context.Context, id string) (*models.Session, error) {
	var session models.Session
	err := r.service.DB(ctx, true).First(&session, "id = ?", id).Error
	if err != nil {
		if frame.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &session, nil
}

// GetByProfileID retrieves sessions for a profile
func (r *sessionRepository) GetByProfileID(ctx context.Context, profileID string) ([]*models.Session, error) {
	var sessions []*models.Session
	err := r.service.DB(ctx, true).Find(&sessions, "profile_id = ?", profileID).Error
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

// Save creates or updates a session record
func (r *sessionRepository) Save(ctx context.Context, session *models.Session) error {
	if session.ID == "" {
		// Create new record
		return r.service.DB(ctx, false).Create(session).Error
	}
	// Update existing record
	return r.service.DB(ctx, false).Save(session).Error
}

// Delete removes a session record by ID
func (r *sessionRepository) Delete(ctx context.Context, id string) error {
	return r.service.DB(ctx, false).Delete(&models.Session{}, "id = ?", id).Error
}

// DeleteExpired removes expired sessions
func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	return r.service.DB(ctx, false).Delete(&models.Session{}, "expires_at < ?", time.Now()).Error
}
