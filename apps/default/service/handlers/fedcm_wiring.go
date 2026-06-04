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
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/pitabwire/frame/cache"
)

// hydraPublicURL returns the Hydra public endpoint URL used by the FedCM
// headless driver for server-to-server authorization calls.
//
// Resolution order:
//  1. FedCMHydraPublicURL config field (explicit override, useful for test
//     containers where admin and public ports differ).
//  2. Oauth2ServiceURI (standard public OAuth2 URI, port 4444 in most setups).
//  3. Oauth2ServiceAdminURI as last-resort fallback (same host different port).
func hydraPublicURL(cfg *aconfig.AuthenticationConfig) string {
	if cfg == nil {
		return ""
	}
	if cfg.Oauth2HydraPublicInternalURL != "" {
		return cfg.Oauth2HydraPublicInternalURL
	}
	if cfg.FedCMHydraPublicURL != "" {
		return cfg.FedCMHydraPublicURL
	}
	if uri := cfg.GetOauth2ServiceURI(); uri != "" {
		return uri
	}
	return cfg.GetOauth2ServiceAdminURI()
}

// newFedCMRevocationKV adapts the application's cache manager to the narrow
// KV interface fedcm.RevocationStore depends on. Returns nil if the cache
// manager does not provide a usable backend.
func newFedCMRevocationKV(cacheMan cache.Manager) fedcm.RevocationKV {
	if cacheMan == nil {
		return nil
	}
	return &fedcmRevocationKV{mgr: cacheMan}
}

type fedcmRevocationKV struct {
	mgr   cache.Manager
	inner cache.Cache[string, string]
}

// getCache lazily initialises and caches the underlying cache instance.
func (k *fedcmRevocationKV) getCache() cache.Cache[string, string] {
	if k.inner != nil {
		return k.inner
	}
	rCache, ok := k.mgr.GetRawCache("defaultCache")
	if !ok {
		return nil
	}
	k.inner = cache.NewGenericCache[string, string](rCache, func(key string) string {
		return key
	})
	return k.inner
}

func (k *fedcmRevocationKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	c := k.getCache()
	if c == nil {
		return nil
	}
	return c.Set(ctx, key, value, ttl)
}

func (k *fedcmRevocationKV) Get(ctx context.Context, key string) (string, bool, error) {
	c := k.getCache()
	if c == nil {
		return "", false, nil
	}
	return c.Get(ctx, key)
}
