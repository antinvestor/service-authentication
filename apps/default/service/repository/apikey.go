package repository

import (
	"context"
	"errors"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame"
	"gorm.io/gorm"
)

type apiKeyRepository struct {
	service *frame.Service
}

// NewAPIKeyRepository creates a new instance of APIKeyRepository
func NewAPIKeyRepository(service *frame.Service) APIKeyRepository {
	return &apiKeyRepository{
		service: service,
	}
}

// GetByID retrieves an API key by ID
func (r *apiKeyRepository) GetByID(ctx context.Context, id string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.service.DB(ctx, true).First(&apiKey, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &apiKey, nil
}

// GetByIDAndProfile retrieves an API key by ID and profile ID
func (r *apiKeyRepository) GetByIDAndProfile(ctx context.Context, id, profileID string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.service.DB(ctx, true).First(&apiKey, "id = ? AND profile_id = ?", id, profileID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &apiKey, nil
}

// GetByKey retrieves an API key by key value
func (r *apiKeyRepository) GetByKey(ctx context.Context, key string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.service.DB(ctx, true).First(&apiKey, "key = ?", key).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &apiKey, nil
}

// GetByProfileID retrieves all API keys for a profile
func (r *apiKeyRepository) GetByProfileID(ctx context.Context, profileID string) ([]*models.APIKey, error) {
	var apiKeys []*models.APIKey
	err := r.service.DB(ctx, true).Find(&apiKeys, "profile_id = ?", profileID).Error
	if err != nil {
		return nil, err
	}
	return apiKeys, nil
}

// Save creates or updates an API key record
func (r *apiKeyRepository) Save(ctx context.Context, apiKey *models.APIKey) error {
	if apiKey.ID == "" {
		// Create new record
		return r.service.DB(ctx, true).Create(apiKey).Error
	}
	// Update existing record
	return r.service.DB(ctx, false).Save(apiKey).Error
}

// Delete removes an API key record by ID and profile ID
func (r *apiKeyRepository) Delete(ctx context.Context, id, profileID string) error {
	return r.service.DB(ctx, false).Delete(&models.APIKey{}, "id = ? AND profile_id = ?", id, profileID).Error
}
