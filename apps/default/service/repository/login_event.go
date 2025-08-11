package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
)

type loginEventRepository struct {
	service *frame.Service
}

// NewLoginEventRepository creates a new instance of LoginEventRepository
func NewLoginEventRepository(service *frame.Service) LoginEventRepository {
	return &loginEventRepository{
		service: service,
	}
}

// GetByID retrieves a login event by ID
func (r *loginEventRepository) GetByID(ctx context.Context, id string) (*models.LoginEvent, error) {
	var loginEvent models.LoginEvent
	err := r.service.DB(ctx, true).First(&loginEvent, "id = ?", id).Error
	if err != nil {
		if frame.ErrorIsNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &loginEvent, nil
}

// Save creates or updates a login event record
func (r *loginEventRepository) Save(ctx context.Context, loginEvent *models.LoginEvent) error {
	if loginEvent.ID == "" {
		// Create new record
		return r.service.DB(ctx, false).Create(loginEvent).Error
	}
	// Update existing record
	return r.service.DB(ctx, false).Save(loginEvent).Error
}

// Delete removes a login event record by ID
func (r *loginEventRepository) Delete(ctx context.Context, id string) error {
	return r.service.DB(ctx, false).Delete(&models.LoginEvent{}, "id = ?", id).Error
}
