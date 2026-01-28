package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/pitabwire/frame/cache"
	"github.com/pitabwire/util"
)

// Rate limit cache key prefix - uses alphanumeric and underscore (NATS-safe)
const rateLimitCachePrefix = "login_rl_ip_"

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	MaxAttempts int           // Maximum attempts allowed
	Window      time.Duration // Time window for rate limiting
}

// DefaultLoginRateLimitConfig returns the default rate limit config for login attempts
func DefaultLoginRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxAttempts: 7,
		Window:      time.Hour,
	}
}

// RateLimitEntry tracks attempts for a single key
type RateLimitEntry struct {
	Attempts  int       `json:"attempts"`
	FirstAt   time.Time `json:"first_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RateLimitResult contains the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool
	AttemptsUsed  int
	AttemptsLeft  int
	RetryAfter    time.Duration
	RetryAfterSec int
}

// hashIP creates a SHA256 hash of the IP address for privacy
func hashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(hash[:])
}

// rateLimitCacheKey generates a cache key for rate limiting by IP
func rateLimitCacheKey(ip string) string {
	return rateLimitCachePrefix + hashIP(ip)
}

// rateLimitCache returns the generic cache for rate limit entries
func (h *AuthServer) rateLimitCache() cache.Cache[string, RateLimitEntry] {
	if h.rateLimitICache == nil {
		rCache, ok := h.cacheMan.GetRawCache(h.config.CacheName)
		if !ok {
			return nil
		}

		h.rateLimitICache = cache.NewGenericCache[string, RateLimitEntry](rCache, func(k string) string {
			return k
		})
	}
	return h.rateLimitICache
}

// CheckLoginRateLimit checks rate limits for the given IP address
// Returns the result indicating if the request is allowed
func (h *AuthServer) CheckLoginRateLimit(ctx context.Context, ip string) RateLimitResult {
	log := util.Log(ctx)
	now := time.Now()

	cacheInst := h.rateLimitCache()
	if cacheInst == nil {
		// Cache not available, allow request but log warning
		log.Warn("rate limit cache not available, allowing request")
		return RateLimitResult{
			Allowed:      true,
			AttemptsUsed: 0,
			AttemptsLeft: h.loginRateLimitConfig.MaxAttempts,
		}
	}

	cacheKey := rateLimitCacheKey(ip)
	entry, found, err := cacheInst.Get(ctx, cacheKey)
	if err != nil {
		log.WithError(err).Warn("rate limit cache read error, allowing request")
		return RateLimitResult{
			Allowed:      true,
			AttemptsUsed: 0,
			AttemptsLeft: h.loginRateLimitConfig.MaxAttempts,
		}
	}

	// If entry doesn't exist or has expired, create a new one
	if !found || now.After(entry.ExpiresAt) {
		newEntry := RateLimitEntry{
			Attempts:  1,
			FirstAt:   now,
			ExpiresAt: now.Add(h.loginRateLimitConfig.Window),
		}

		if setErr := cacheInst.Set(ctx, cacheKey, newEntry, h.loginRateLimitConfig.Window); setErr != nil {
			log.WithError(setErr).Warn("failed to set rate limit entry in cache")
		}

		return RateLimitResult{
			Allowed:      true,
			AttemptsUsed: 1,
			AttemptsLeft: h.loginRateLimitConfig.MaxAttempts - 1,
		}
	}

	// Check if limit exceeded
	if entry.Attempts >= h.loginRateLimitConfig.MaxAttempts {
		retryAfter := entry.ExpiresAt.Sub(now)
		log.WithFields(map[string]any{
			"ip_hash":       hashIP(ip)[:16] + "...",
			"attempts":      entry.Attempts,
			"retry_after_s": int(retryAfter.Seconds()),
		}).Warn("login rate limit exceeded for IP")

		return RateLimitResult{
			Allowed:       false,
			AttemptsUsed:  entry.Attempts,
			AttemptsLeft:  0,
			RetryAfter:    retryAfter,
			RetryAfterSec: int(retryAfter.Seconds()),
		}
	}

	// Increment counter
	entry.Attempts++
	ttlRemaining := entry.ExpiresAt.Sub(now)
	if setErr := cacheInst.Set(ctx, cacheKey, entry, ttlRemaining); setErr != nil {
		log.WithError(setErr).Warn("failed to update rate limit entry in cache")
	}

	return RateLimitResult{
		Allowed:      true,
		AttemptsUsed: entry.Attempts,
		AttemptsLeft: h.loginRateLimitConfig.MaxAttempts - entry.Attempts,
	}
}

// ResetLoginRateLimit resets rate limits after successful login for the given IP
func (h *AuthServer) ResetLoginRateLimit(ctx context.Context, ip string) {
	cacheInst := h.rateLimitCache()
	if cacheInst == nil {
		return
	}

	cacheKey := rateLimitCacheKey(ip)
	if err := cacheInst.Delete(ctx, cacheKey); err != nil {
		util.Log(ctx).WithError(err).Debug("failed to delete rate limit entry from cache")
	}
}

// ResetAllLoginRateLimits is a no-op for cache-based rate limiting
// as cache entries will naturally expire. This is kept for test compatibility.
func (h *AuthServer) ResetAllLoginRateLimits() {
	// Cache entries expire naturally based on TTL.
	// For testing purposes, individual entries can be reset via ResetLoginRateLimit.
}
