package handlers

import (
	"testing"
	"time"

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

func (s *RateLimiterTestSuite) TestRateLimitCacheKey() {
	key := rateLimitCacheKey("192.168.1.1")
	s.Contains(key, rateLimitCachePrefix)
	s.Len(key, len(rateLimitCachePrefix)+64)
}

func (s *RateLimiterTestSuite) TestDefaultLoginRateLimitConfig() {
	cfg := DefaultLoginRateLimitConfig()
	s.Equal(7, cfg.MaxAttempts)
	s.Equal(time.Hour, cfg.Window)
}

func (s *RateLimiterTestSuite) TestRateLimitEntry_Fields() {
	now := time.Now()
	entry := RateLimitEntry{
		Attempts:  3,
		FirstAt:   now,
		ExpiresAt: now.Add(time.Hour),
	}
	s.Equal(3, entry.Attempts)
	s.Equal(now, entry.FirstAt)
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
