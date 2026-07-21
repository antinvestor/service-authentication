// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pitabwire/frame/v2/cache"
	"github.com/pitabwire/util"
)

// RateLimitConfig holds configuration for rate limiting.
type RateLimitConfig struct {
	MaxAttempts int           // Maximum attempts allowed
	Window      time.Duration // Time window for rate limiting
}

// DefaultLoginRateLimitConfig returns the default rate limit config for login attempts.
func DefaultLoginRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		MaxAttempts: 7,
		Window:      time.Hour,
	}
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	Allowed       bool
	AttemptsUsed  int
	AttemptsLeft  int
	RetryAfter    time.Duration
	RetryAfterSec int
}

// hashIP creates a SHA256 hash of the rate-limit key (IP or compound key) for privacy.
func hashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(hash[:])
}

// rateLimitBucketKey builds a fixed-window counter key for the given identity and time.
func rateLimitBucketKey(key string, window time.Duration, now time.Time) string {
	windowSecs := int64(window.Seconds())
	if windowSecs <= 0 {
		windowSecs = int64(time.Hour.Seconds())
	}
	bucket := now.Unix() / windowSecs
	// Underscore separator (NATS JetStream KV-safe; no colon).
	return fmt.Sprintf("%s%s_%d", rateLimitCachePrefix, hashIP(key), bucket)
}

func (h *AuthServer) rateLimitConfig() RateLimitConfig {
	cfg := h.loginRateLimitConfig
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultLoginRateLimitConfig().MaxAttempts
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultLoginRateLimitConfig().Window
	}
	return cfg
}

// rawSharedCache returns the Frame RawCache for this service (rate limits, SA
// claims, FedCM, login events). Always go through cache.Manager — never open
// redis/valkey/NATS clients directly (golang-patterns).
func (h *AuthServer) rawSharedCache() cache.RawCache {
	if h == nil || h.cacheMan == nil || h.config == nil {
		return nil
	}
	name := h.config.CacheName
	if name == "" {
		name = "defaultCache"
	}
	raw, ok := h.cacheMan.GetRawCache(name)
	if !ok {
		return nil
	}
	return raw
}

// rawRateLimitCache is an alias kept for call-site clarity in rate limiting.
func (h *AuthServer) rawRateLimitCache() cache.RawCache {
	return h.rawSharedCache()
}

func denyRateLimitResult(cfg RateLimitConfig, retryAfter time.Duration) RateLimitResult {
	if retryAfter < 0 {
		retryAfter = 0
	}
	return RateLimitResult{
		Allowed:       false,
		AttemptsUsed:  cfg.MaxAttempts,
		AttemptsLeft:  0,
		RetryAfter:    retryAfter,
		RetryAfterSec: int(retryAfter.Seconds()),
	}
}

func windowRetryAfter(window time.Duration, now time.Time) time.Duration {
	windowSecs := int64(window.Seconds())
	if windowSecs <= 0 {
		windowSecs = int64(time.Hour.Seconds())
	}
	endOfWindow := time.Unix((now.Unix()/windowSecs+1)*windowSecs, 0).UTC()
	retryAfter := endOfWindow.Sub(now)
	if retryAfter < 0 {
		return 0
	}
	return retryAfter
}

// CheckLoginRateLimit checks rate limits for the given key (IP or compound identity).
//
// Semantics:
//   - Atomic fixed-window counter via cache.Increment (safe under concurrency)
//   - Fail-closed when the cache is unavailable or increment fails — login
//     surfaces must not become unbounded under infrastructure faults
func (h *AuthServer) CheckLoginRateLimit(ctx context.Context, key string) RateLimitResult {
	log := util.Log(ctx)
	cfg := h.rateLimitConfig()
	now := time.Now().UTC()
	retryAfter := windowRetryAfter(cfg.Window, now)

	raw := h.rawRateLimitCache()
	if raw == nil {
		log.Error("rate limit cache not available, denying request")
		return denyRateLimitResult(cfg, retryAfter)
	}

	bucketKey := rateLimitBucketKey(key, cfg.Window, now)
	count, err := raw.Increment(ctx, bucketKey, 1)
	if err != nil {
		log.WithError(err).Error("rate limit increment failed, denying request")
		return denyRateLimitResult(cfg, retryAfter)
	}

	// Best-effort TTL so backends that support it reclaim the bucket.
	// Backends without per-key TTL still isolate counts by window id in the key.
	if count == 1 {
		if expErr := raw.Expire(ctx, bucketKey, cfg.Window+time.Second); expErr != nil {
			log.WithError(expErr).Debug("rate limit bucket expire failed")
		}
	}

	if count > int64(cfg.MaxAttempts) {
		log.WithFields(map[string]any{
			"key_hash":      hashIP(key)[:16] + "...",
			"attempts":      count,
			"retry_after_s": int(retryAfter.Seconds()),
		}).Warn("login rate limit exceeded")

		return RateLimitResult{
			Allowed:       false,
			AttemptsUsed:  int(count),
			AttemptsLeft:  0,
			RetryAfter:    retryAfter,
			RetryAfterSec: int(retryAfter.Seconds()),
		}
	}

	return RateLimitResult{
		Allowed:      true,
		AttemptsUsed: int(count),
		AttemptsLeft: cfg.MaxAttempts - int(count),
	}
}

// ResetLoginRateLimit clears the current window counter after successful auth.
func (h *AuthServer) ResetLoginRateLimit(ctx context.Context, key string) {
	raw := h.rawRateLimitCache()
	if raw == nil {
		return
	}

	cfg := h.rateLimitConfig()
	bucketKey := rateLimitBucketKey(key, cfg.Window, time.Now().UTC())
	if err := raw.Delete(ctx, bucketKey); err != nil {
		util.Log(ctx).WithError(err).Debug("failed to delete rate limit bucket from cache")
	}
}

// ResetAllLoginRateLimits is a no-op for cache-based rate limiting
// as cache entries will naturally expire. Kept for test compatibility.
func (h *AuthServer) ResetAllLoginRateLimits() {
	// Cache entries expire naturally based on TTL / window id rotation.
	// For testing, reset individual keys via ResetLoginRateLimit.
}
