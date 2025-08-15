package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
)

type loginRepository struct {
	service *frame.Service
}

// NewLoginRepository creates a new instance of LoginRepository
func NewLoginRepository(service *frame.Service) LoginRepository {
	return &loginRepository{
		service: service,
	}
}

// GetByID retrieves a login by ID
func (r *loginRepository) GetByID(ctx context.Context, id string) (*models.Login, error) {
	var login models.Login
	err := r.service.DB(ctx, true).First(&login, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &login, nil
}

// GetByProfileID retrieves a login by profile ID
func (r *loginRepository) GetByProfileID(ctx context.Context, profileID string) (*models.Login, error) {
	var login models.Login
	err := r.service.DB(ctx, true).First(&login, "profile_id = ?", profileID).Error
	if err != nil {
return nil, err
	}
	return &login, nil
}

// Save creates or updates a login record
func (r *loginRepository) Save(ctx context.Context, login *models.Login) error {
	if login.ID == "" {
		// Create new record
		return r.service.DB(ctx, false).Create(login).Error
	}
	// Update existing record
	return r.service.DB(ctx, false).Save(login).Error
}

// Delete removes a login record by ID
func (r *loginRepository) Delete(ctx context.Context, id string) error {
	return r.service.DB(ctx, false).Delete(&models.Login{}, "id = ?", id).Error
}
