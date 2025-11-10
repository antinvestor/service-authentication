package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/datastore"
	"github.com/pitabwire/frame/datastore/pool"
	"github.com/pitabwire/frame/workerpool"
	"github.com/pitabwire/util"
)

type apiKeyRepository struct {
	datastore.BaseRepository[*models.APIKey]
}

// NewAPIKeyRepository creates a new instance of APIKeyRepository
func NewAPIKeyRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) APIKeyRepository {
	return &apiKeyRepository{
		BaseRepository: datastore.NewBaseRepository[*models.APIKey](
			ctx, dbPool, workMan, func() *models.APIKey { return &models.APIKey{} },
		),
	}
}

// GetByID retrieves an API key by ID
func (r *apiKeyRepository) GetByID(ctx context.Context, id string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.Pool().DB(ctx, true).Where("id = ?", id).First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

// GetByIDAndProfile retrieves an API key by ID and profile ID
func (r *apiKeyRepository) GetByIDAndProfile(ctx context.Context, id, profileID string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.Pool().DB(ctx, true).Where("id = ? AND profile_id = ? ", id, profileID).First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

// GetByKey retrieves an API key by key value
func (r *apiKeyRepository) GetByKey(ctx context.Context, key string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.Pool().DB(ctx, true).Where("key = ?", key).First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

// GetByProfileID retrieves all API keys for a profile
func (r *apiKeyRepository) GetByProfileID(ctx context.Context, profileID string) ([]*models.APIKey, error) {
	var apiKeys []*models.APIKey
	err := r.Pool().DB(ctx, true).Where("profile_id = ?", profileID).Find(&apiKeys).Error
	if err != nil {
		return nil, err
	}
	return apiKeys, nil
}

// Save creates or updates an API key record
func (r *apiKeyRepository) Save(ctx context.Context, apiKey *models.APIKey) error {
	if apiKey.ID == "" {
		// Create new record
		return r.Pool().DB(ctx, true).Create(apiKey).Error
	}
	// Update existing record
	return r.Pool().DB(ctx, false).Save(apiKey).Error
}

// DeleteByProfile removes an API key record by ID and profile ID
func (r *apiKeyRepository) DeleteByProfile(ctx context.Context, id, profileID string) error {
	logger := util.Log(ctx)
	logger.Debug("APIKeyRepository.Delete: starting deletion", "id", id, "profileID", profileID)

	// First, let's verify the record exists before deletion
	var existingKey models.APIKey
	db := r.Pool().DB(ctx, true) // Use read connection for existence check
	checkResult := db.Where("id = ? AND profile_id = ?", id, profileID).First(&existingKey)

	if checkResult.Error != nil {
		if data.ErrorIsNoRows(checkResult.Error) {
			logger.Debug("APIKeyRepository.Delete: API key not found for deletion", "id", id, "profileID", profileID)
			return nil // Already deleted or doesn't exist
		}
		logger.Error("APIKeyRepository.Delete: error checking existence", "error", checkResult.Error, "id", id, "profileID", profileID)
		return checkResult.Error
	}

	logger.Debug("APIKeyRepository.Delete: found existing key before deletion", "id", id, "profileID", profileID, "keyName", existingKey.Name, "deletedAt", existingKey.DeletedAt)

	// Now perform the deletion using write connection
	writeDB := r.Pool().DB(ctx, false)
	result := writeDB.Where("id = ? AND profile_id = ?", id, profileID).Delete(&existingKey)

	logger.Debug("APIKeyRepository.Delete: deletion result", "rowsAffected", result.RowsAffected, "error", result.Error)

	if result.Error != nil {
		logger.Error("APIKeyRepository.Delete: deletion failed", "error", result.Error, "id", id, "profileID", profileID)
		return result.Error
	}

	if result.RowsAffected == 0 {
		logger.Warn("APIKeyRepository.Delete: no rows affected - API key may not exist", "id", id, "profileID", profileID)
	} else {
		logger.Debug("APIKeyRepository.Delete: deletion successful", "id", id, "profileID", profileID, "rowsAffected", result.RowsAffected)
	}

	return nil
}
