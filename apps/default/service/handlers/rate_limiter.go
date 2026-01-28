package handlers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pitabwire/util"
)

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

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	config RateLimitConfig
	mu     sync.RWMutex
	store  map[string]*RateLimitEntry
}

// NewRateLimiter creates a new rate limiter with the given config
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config: config,
		store:  make(map[string]*RateLimitEntry),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// cleanup periodically removes expired entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, entry := range rl.store {
			if now.After(entry.ExpiresAt) {
				delete(rl.store, key)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitResult contains the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool
	AttemptsUsed  int
	AttemptsLeft  int
	RetryAfter    time.Duration
	RetryAfterSec int
}

// Check checks if an action is allowed for the given key and increments the counter
func (rl *RateLimiter) Check(ctx context.Context, key string) RateLimitResult {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.store[key]

	// If entry doesn't exist or has expired, create a new one
	if !exists || now.After(entry.ExpiresAt) {
		rl.store[key] = &RateLimitEntry{
			Attempts:  1,
			FirstAt:   now,
			ExpiresAt: now.Add(rl.config.Window),
		}
		return RateLimitResult{
			Allowed:      true,
			AttemptsUsed: 1,
			AttemptsLeft: rl.config.MaxAttempts - 1,
		}
	}

	// Check if limit exceeded
	if entry.Attempts >= rl.config.MaxAttempts {
		retryAfter := entry.ExpiresAt.Sub(now)
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
	return RateLimitResult{
		Allowed:      true,
		AttemptsUsed: entry.Attempts,
		AttemptsLeft: rl.config.MaxAttempts - entry.Attempts,
	}
}

// Peek checks the current state without incrementing the counter
func (rl *RateLimiter) Peek(ctx context.Context, key string) RateLimitResult {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	entry, exists := rl.store[key]

	if !exists || now.After(entry.ExpiresAt) {
		return RateLimitResult{
			Allowed:      true,
			AttemptsUsed: 0,
			AttemptsLeft: rl.config.MaxAttempts,
		}
	}

	if entry.Attempts >= rl.config.MaxAttempts {
		retryAfter := entry.ExpiresAt.Sub(now)
		return RateLimitResult{
			Allowed:       false,
			AttemptsUsed:  entry.Attempts,
			AttemptsLeft:  0,
			RetryAfter:    retryAfter,
			RetryAfterSec: int(retryAfter.Seconds()),
		}
	}

	return RateLimitResult{
		Allowed:      true,
		AttemptsUsed: entry.Attempts,
		AttemptsLeft: rl.config.MaxAttempts - entry.Attempts,
	}
}

// Reset resets the rate limit for a key (e.g., after successful login)
func (rl *RateLimiter) Reset(ctx context.Context, key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.store, key)
}

// ResetAll clears all rate limit entries (useful for testing)
func (rl *RateLimiter) ResetAll() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.store = make(map[string]*RateLimitEntry)
}

// loginRateLimitKey generates a rate limit key for login attempts
func loginRateLimitKey(keyType, value string) string {
	return fmt.Sprintf("login_rl:%s:%s", keyType, value)
}

// CheckLoginRateLimit checks rate limits for both IP and contact
// Returns the most restrictive result
func (h *AuthServer) CheckLoginRateLimit(ctx context.Context, ip, contact string) RateLimitResult {
	log := util.Log(ctx)

	// Check IP rate limit
	ipKey := loginRateLimitKey("ip", ip)
	ipResult := h.loginRateLimiter.Check(ctx, ipKey)

	if !ipResult.Allowed {
		log.WithFields(map[string]any{
			"ip":            ip,
			"attempts":      ipResult.AttemptsUsed,
			"retry_after_s": ipResult.RetryAfterSec,
		}).Warn("login rate limit exceeded for IP")
		return ipResult
	}

	// Check contact rate limit (if provided)
	if contact != "" {
		contactKey := loginRateLimitKey("contact", contact)
		contactResult := h.loginRateLimiter.Check(ctx, contactKey)

		if !contactResult.Allowed {
			log.WithFields(map[string]any{
				"contact_prefix": contact[:min(3, len(contact))] + "***",
				"attempts":       contactResult.AttemptsUsed,
				"retry_after_s":  contactResult.RetryAfterSec,
			}).Warn("login rate limit exceeded for contact")
			return contactResult
		}

		// Return the more restrictive result
		if contactResult.AttemptsLeft < ipResult.AttemptsLeft {
			return contactResult
		}
	}

	return ipResult
}

// ResetLoginRateLimit resets rate limits after successful login
func (h *AuthServer) ResetLoginRateLimit(ctx context.Context, ip, contact string) {
	ipKey := loginRateLimitKey("ip", ip)
	h.loginRateLimiter.Reset(ctx, ipKey)

	if contact != "" {
		contactKey := loginRateLimitKey("contact", contact)
		h.loginRateLimiter.Reset(ctx, contactKey)
	}
}

// ResetAllLoginRateLimits clears all login rate limits (useful for testing)
func (h *AuthServer) ResetAllLoginRateLimits() {
	if h.loginRateLimiter != nil {
		h.loginRateLimiter.ResetAll()
	}
}
