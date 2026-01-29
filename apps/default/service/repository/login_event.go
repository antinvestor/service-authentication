package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type loginEventRepository struct {
	datastore.BaseRepository[*models.LoginEvent]
}

// NewLoginEventRepository creates a new instance of LoginEventRepository
func NewLoginEventRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) LoginEventRepository {
	return &loginEventRepository{
		BaseRepository: datastore.NewBaseRepository[*models.LoginEvent](
			ctx, dbPool, workMan, func() *models.LoginEvent { return &models.LoginEvent{} },
		),
	}
}

// GetByID retrieves a login event by ID
func (r *loginEventRepository) GetByID(ctx context.Context, id string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := r.Pool().DB(ctx, true).First(&loginEvent, "id = ?", id).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

// GetByLoginChallenge retrieves a login event by the Hydra login challenge ID
func (r *loginEventRepository) GetByLoginChallenge(ctx context.Context, loginChallengeID string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := r.Pool().DB(ctx, true).First(&loginEvent, "login_challenge_id = ?", loginChallengeID).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

// Save creates or updates a login event record
func (r *loginEventRepository) Save(ctx context.Context, loginEvent *models.LoginEvent) error {
	// Create new record
	return r.Pool().DB(ctx, false).Create(loginEvent).Error
}

// Delete removes a login event record by ID
func (r *loginEventRepository) Delete(ctx context.Context, id string) error {
	return r.Pool().DB(ctx, false).Delete(&models.LoginEvent{}, "id = ?", id).Error
}

// GetMostRecentByProfileID retrieves the most recent login event for a profile
func (r *loginEventRepository) GetMostRecentByProfileID(ctx context.Context, profileID string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := r.Pool().DB(ctx, true).
		Where("profile_id = ?", profileID).
		Order("created_at DESC").
		First(&loginEvent).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, err
		}
		return nil, err
	}
	return &loginEvent, nil
}

// GetByOauth2SessionID retrieves the login event linked to a Hydra OAuth2 session
func (r *loginEventRepository) GetByOauth2SessionID(ctx context.Context, oauth2SessionID string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := r.Pool().DB(ctx, true).
		Where("oauth2_session_id = ?", oauth2SessionID).
		Order("created_at DESC").
		First(&loginEvent).Error
	if err != nil {
		if data.ErrorIsNoRows(err) {
			return nil, err
		}
		return nil, err
	}
	return &loginEvent, nil
}
