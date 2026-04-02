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
