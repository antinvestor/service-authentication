package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/utils"
	"github.com/pitabwire/frame/cache"
	"github.com/pitabwire/util"
)

// Cache key prefix for recent logins
// Format: recent_login_{contact_hash}_{session_id}
// We use session_id (browser session) to tie trust to a specific browser session
const recentLoginCachePrefix = "recent_login_"

// recentLoginCache returns the cache for storing recent login information.
// Uses the same cache manager as login events but with a different key prefix.
func (h *AuthServer) recentLoginCache() cache.Cache[string, models.RecentLogin] {
	rCache, ok := h.cacheMan.GetRawCache(h.config.CacheName)
	if !ok {
		return nil
	}

	return cache.NewGenericCache[string, models.RecentLogin](rCache, func(k string) string {
		return k
	})
}

// buildRecentLoginCacheKey creates a cache key for recent login lookups.
// The key is based on a hash of the contact (for privacy) and the session ID
// to tie the trust to a specific browser/device session.
func buildRecentLoginCacheKey(contact, sessionID string) string {
	// Use a hash of the contact to avoid storing PII in cache keys
	contactHash := utils.HashStringSecret(contact)
	return fmt.Sprintf("%s%s_%s", recentLoginCachePrefix, contactHash, sessionID)
}

// GetRecentLogin checks if there's a recent successful login for the given contact
// from the current session. Returns the recent login if found and still valid,
// nil otherwise.
func (h *AuthServer) GetRecentLogin(ctx context.Context, contact string) (*models.RecentLogin, error) {
	log := util.Log(ctx)

	// Check if feature is enabled
	if h.config.RecentLoginDuration <= 0 {
		log.Debug("recent login feature is disabled")
		return nil, nil
	}

	sessionID := utils.SessionIDFromContext(ctx)
	if sessionID == "" {
		log.Debug("no session ID in context, cannot check recent login")
		return nil, nil
	}

	recentCache := h.recentLoginCache()
	if recentCache == nil {
		log.Warn("recent login cache not available")
		return nil, nil
	}

	cacheKey := buildRecentLoginCacheKey(contact, sessionID)
	recentLogin, found, err := recentCache.Get(ctx, cacheKey)
	if err != nil {
		log.WithError(err).WithField("cache_key", cacheKey).
			Error("error retrieving recent login from cache")
		return nil, err
	}

	if !found {
		log.WithField("contact_prefix", contact[:min(3, len(contact))]+"***").
			Debug("no recent login found for contact")
		return nil, nil
	}

	// Verify the login is still within the valid duration
	expiresAt := recentLogin.LoginAt.Add(time.Duration(h.config.RecentLoginDuration) * time.Second)
	if time.Now().After(expiresAt) {
		log.Debug("recent login has expired")
		return nil, nil
	}

	log.WithFields(map[string]any{
		"profile_id":  recentLogin.ProfileID,
		"login_at":    recentLogin.LoginAt,
		"expires_at":  expiresAt,
		"contact_prefix": contact[:min(3, len(contact))] + "***",
	}).Info("found valid recent login - user can skip verification")

	return &recentLogin, nil
}

// StoreRecentLogin stores a successful login in the cache for future use.
// This allows the user to skip verification on subsequent logins from the same session.
func (h *AuthServer) StoreRecentLogin(ctx context.Context, contact string, recentLogin *models.RecentLogin) error {
	log := util.Log(ctx)

	// Check if feature is enabled
	if h.config.RecentLoginDuration <= 0 {
		log.Debug("recent login feature is disabled, not storing")
		return nil
	}

	sessionID := utils.SessionIDFromContext(ctx)
	if sessionID == "" {
		log.Debug("no session ID in context, cannot store recent login")
		return nil
	}

	recentCache := h.recentLoginCache()
	if recentCache == nil {
		log.Warn("recent login cache not available")
		return nil
	}

	// Set the session ID and login time
	recentLogin.SessionID = sessionID
	recentLogin.LoginAt = time.Now()

	cacheKey := buildRecentLoginCacheKey(contact, sessionID)
	ttl := time.Duration(h.config.RecentLoginDuration) * time.Second

	if err := recentCache.Set(ctx, cacheKey, *recentLogin, ttl); err != nil {
		log.WithError(err).Error("failed to store recent login in cache")
		return err
	}

	log.WithFields(map[string]any{
		"profile_id":     recentLogin.ProfileID,
		"session_id":     sessionID,
		"ttl_seconds":    h.config.RecentLoginDuration,
		"contact_prefix": contact[:min(3, len(contact))] + "***",
	}).Info("stored recent login for future verification skip")

	return nil
}

// ClearRecentLogin removes a recent login from the cache.
// This can be used when a user explicitly logs out or when security requires re-verification.
func (h *AuthServer) ClearRecentLogin(ctx context.Context, contact string) error {
	log := util.Log(ctx)

	sessionID := utils.SessionIDFromContext(ctx)
	if sessionID == "" {
		return nil
	}

	recentCache := h.recentLoginCache()
	if recentCache == nil {
		return nil
	}

	cacheKey := buildRecentLoginCacheKey(contact, sessionID)
	if err := recentCache.Delete(ctx, cacheKey); err != nil {
		log.WithError(err).WithField("cache_key", cacheKey).
			Warn("failed to clear recent login from cache")
		return err
	}

	log.Debug("cleared recent login from cache")
	return nil
}
