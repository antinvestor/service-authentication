package repository

import (
	"context"
	"errors"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
	"gorm.io/gorm"
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

// GetByProfileHash retrieves a login by profile hash
func (r *loginRepository) GetByProfileHash(ctx context.Context, profileHash string) (*models.Login, error) {
	var login models.Login
	err := r.service.DB(ctx, true).First(&login, "profile_hash = ?", profileHash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
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
