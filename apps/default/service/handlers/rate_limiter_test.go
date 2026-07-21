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
	"sync"
	"testing"
	"time"

	authconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/pitabwire/frame/v2/cache"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RateLimiterTestSuite struct {
	suite.Suite
}

func (s *RateLimiterTestSuite) TestHashIP_Consistent() {
	hash1 := hashIP("192.168.1.1")
	hash2 := hashIP("192.168.1.1")
	s.Equal(hash1, hash2)
}

func (s *RateLimiterTestSuite) TestHashIP_DifferentIPs() {
	hash1 := hashIP("192.168.1.1")
	hash2 := hashIP("192.168.1.2")
	s.NotEqual(hash1, hash2)
}

func (s *RateLimiterTestSuite) TestHashIP_Length() {
	hash := hashIP("10.0.0.1")
	s.Len(hash, 64, "SHA256 hex should be 64 chars")
}

func (s *RateLimiterTestSuite) TestRateLimitBucketKey() {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := rateLimitBucketKey("192.168.1.1", time.Hour, now)
	s.Contains(key, rateLimitCachePrefix)
	// Underscore separator keeps keys NATS JetStream KV-safe (no colon).
	s.NotContains(key, ":")
	s.Contains(key, "_")
}

func (s *RateLimiterTestSuite) TestDefaultLoginRateLimitConfig() {
	cfg := DefaultLoginRateLimitConfig()
	s.Equal(7, cfg.MaxAttempts)
	s.Equal(time.Hour, cfg.Window)
}

func (s *RateLimiterTestSuite) TestRateLimitResult_Fields() {
	result := RateLimitResult{
		Allowed:       true,
		AttemptsUsed:  2,
		AttemptsLeft:  5,
		RetryAfter:    30 * time.Second,
		RetryAfterSec: 30,
	}
	s.True(result.Allowed)
	s.Equal(2, result.AttemptsUsed)
	s.Equal(5, result.AttemptsLeft)
}

func TestRateLimiter(t *testing.T) {
	suite.Run(t, new(RateLimiterTestSuite))
}

func newRateLimitTestServer(t *testing.T, maxAttempts int) *AuthServer {
	t.Helper()
	cacheMan := cache.NewManager()
	cacheMan.AddCache("defaultCache", cache.NewInMemoryCache())
	return &AuthServer{
		config: &authconfig.AuthenticationConfig{
			CacheName: "defaultCache",
		},
		cacheMan: cacheMan,
		loginRateLimitConfig: RateLimitConfig{
			MaxAttempts: maxAttempts,
			Window:      time.Hour,
		},
	}
}

func TestCheckLoginRateLimit_AllowsUntilMaxThenDenies(t *testing.T) {
	t.Parallel()
	h := newRateLimitTestServer(t, 3)
	ctx := context.Background()
	ip := "203.0.113.10"

	for i := 1; i <= 3; i++ {
		result := h.CheckLoginRateLimit(ctx, ip)
		require.True(t, result.Allowed, "attempt %d should be allowed", i)
		require.Equal(t, i, result.AttemptsUsed)
		require.Equal(t, 3-i, result.AttemptsLeft)
	}

	denied := h.CheckLoginRateLimit(ctx, ip)
	require.False(t, denied.Allowed)
	require.Equal(t, 0, denied.AttemptsLeft)
	require.Greater(t, denied.RetryAfterSec, 0)
}

func TestCheckLoginRateLimit_ResetClearsWindow(t *testing.T) {
	t.Parallel()
	h := newRateLimitTestServer(t, 2)
	ctx := context.Background()
	ip := "203.0.113.11"

	require.True(t, h.CheckLoginRateLimit(ctx, ip).Allowed)
	require.True(t, h.CheckLoginRateLimit(ctx, ip).Allowed)
	require.False(t, h.CheckLoginRateLimit(ctx, ip).Allowed)

	h.ResetLoginRateLimit(ctx, ip)

	result := h.CheckLoginRateLimit(ctx, ip)
	require.True(t, result.Allowed)
	require.Equal(t, 1, result.AttemptsUsed)
}

func TestCheckLoginRateLimit_FailClosedWithoutCache(t *testing.T) {
	t.Parallel()
	h := &AuthServer{
		loginRateLimitConfig: DefaultLoginRateLimitConfig(),
	}
	result := h.CheckLoginRateLimit(context.Background(), "203.0.113.12")
	require.False(t, result.Allowed, "missing cache must deny, not fail open")
}

func TestCheckLoginRateLimit_IsolatesKeys(t *testing.T) {
	t.Parallel()
	h := newRateLimitTestServer(t, 1)
	ctx := context.Background()

	require.True(t, h.CheckLoginRateLimit(ctx, "203.0.113.20").Allowed)
	require.False(t, h.CheckLoginRateLimit(ctx, "203.0.113.20").Allowed)
	require.True(t, h.CheckLoginRateLimit(ctx, "203.0.113.21").Allowed,
		"a different IP must have an independent budget")
}

func TestCheckLoginRateLimit_ConcurrentIncrementsDoNotBypassLimit(t *testing.T) {
	t.Parallel()
	const maxAttempts = 20
	const workers = 50

	h := newRateLimitTestServer(t, maxAttempts)
	ctx := context.Background()
	ip := "203.0.113.30"

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
		denied  int
	)

	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			result := h.CheckLoginRateLimit(ctx, ip)
			mu.Lock()
			if result.Allowed {
				allowed++
			} else {
				denied++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	require.Equal(t, maxAttempts, allowed, "exactly MaxAttempts should succeed under contention")
	require.Equal(t, workers-maxAttempts, denied)
}
