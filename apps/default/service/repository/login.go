package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
)

type loginRepository struct {
	datastore.BaseRepository[*models.Login]
}

// NewLoginRepository creates a new instance of LoginRepository
func NewLoginRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) LoginRepository {
	return &loginRepository{
		BaseRepository: datastore.NewBaseRepository[*models.Login](
		ctx, dbPool, workMan, func() *models.Login { return &models.Login{} },
	),
	}
}

// GetByID retrieves a login by ID
func (r *loginRepository) GetByID(ctx context.Context, id string) (*models.Login, error) {
	var login models.Login
	err := r.Pool().DB(ctx, true).First(&login, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &login, nil
}

// GetByProfileID retrieves a login by profile ID
func (r *loginRepository) GetByProfileID(ctx context.Context, profileID string) (*models.Login, error) {
	var login models.Login
	err := r.Pool().DB(ctx, true).First(&login, "profile_id = ?", profileID).Error
	if err != nil {
		return nil, err
	}
	return &login, nil
}

// Save creates or updates a login record
func (r *loginRepository) Save(ctx context.Context, login *models.Login) error {
	if login.ID == "" {
		// Create new record
		return r.Pool().DB(ctx, false).Create(login).Error
	}
	// Update existing record
	return r.Pool().DB(ctx, false).Save(login).Error
}
