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
	"net/http"
	"net/http/httptest"
	"testing"

	authconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/nativecredentials"
	"github.com/pitabwire/frame/cache"
	"github.com/stretchr/testify/require"
)

func TestExternalTokenEndpointPrefersConfiguredPublicOrigin(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{FedCMPublicOrigin: "https://accounts.example.com/"}}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "attacker.example"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "http")

	require.Equal(t, "https://accounts.example.com/oauth2/token", h.externalTokenEndpoint(req))
}

func TestRejectNativeReplayFailsClosedWithoutCache(t *testing.T) {
	h := &AuthServer{config: &authconfig.AuthenticationConfig{CacheName: "auth-cache"}}
	identity := &nativecredentials.Identity{Provider: nativecredentials.ProviderGoogle, TokenHash: "abc123"}

	replayed, err := h.rejectNativeReplay(context.Background(), identity)
	require.False(t, replayed)
	require.Error(t, err)
}

func TestRejectNativeReplayRejectsSecondUse(t *testing.T) {
	cacheMan := cache.NewManager()
	cacheMan.AddCache("auth-cache", cache.NewInMemoryCache())
	h := &AuthServer{
		config:   &authconfig.AuthenticationConfig{CacheName: "auth-cache"},
		cacheMan: cacheMan,
	}
	identity := &nativecredentials.Identity{Provider: nativecredentials.ProviderGoogle, TokenHash: "abc123"}

	replayed, err := h.rejectNativeReplay(context.Background(), identity)
	require.NoError(t, err)
	require.False(t, replayed)

	replayed, err = h.rejectNativeReplay(context.Background(), identity)
	require.NoError(t, err)
	require.True(t, replayed)
}

func TestFedCMExchangeCacheUsesConfiguredCacheName(t *testing.T) {
	cacheMan := cache.NewManager()
	cacheMan.AddCache("auth-cache", cache.NewInMemoryCache())
	h := &AuthServer{
		config:   &authconfig.AuthenticationConfig{CacheName: "auth-cache"},
		cacheMan: cacheMan,
	}

	c, err := h.fedcmExchangeCache()
	require.NoError(t, err)
	require.NotNil(t, c)
}
