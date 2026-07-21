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
	"crypto"
	"strings"
	"sync"
	"time"

	"github.com/pitabwire/util"
)

// jwkSigningCacheEntry holds a parsed Hydra private signing key for private_key_jwt.
// Process-local only: private key material must not go into the shared Valkey cache.
// TTL is long enough to absorb Hydra admin blips without serving rotated keys for hours.
type jwkSigningCacheEntry struct {
	setName string
	signer  crypto.Signer
	kid     string
	expires time.Time
}

// jwkSigningCache is a tiny per-pod map. Not used for multi-node coordination.
type jwkSigningCache struct {
	mu    sync.RWMutex
	bySet map[string]jwkSigningCacheEntry
}

func newJWKSigningCache() *jwkSigningCache {
	return &jwkSigningCache{bySet: make(map[string]jwkSigningCacheEntry)}
}

func (c *jwkSigningCache) get(setName string) (crypto.Signer, string, bool) {
	if c == nil {
		return nil, "", false
	}
	now := time.Now()
	c.mu.RLock()
	e, ok := c.bySet[setName]
	c.mu.RUnlock()
	if !ok || e.signer == nil || now.After(e.expires) {
		return nil, "", false
	}
	return e.signer, e.kid, true
}

func (c *jwkSigningCache) set(setName string, signer crypto.Signer, kid string, ttl time.Duration) {
	if c == nil || signer == nil || setName == "" {
		return
	}
	if ttl <= 0 {
		ttl = jwkSigningCacheTTL
	}
	c.mu.Lock()
	c.bySet[setName] = jwkSigningCacheEntry{
		setName: setName,
		signer:  signer,
		kid:     kid,
		expires: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

// getSigningKey returns a crypto.Signer for the named JWK set, using the
// process-local cache on the warm path. Cold path hits Hydra admin once and
// caches the parsed private key so subsequent private_key_jwt mints survive
// short Hydra admin outages within jwkSigningCacheTTL.
func (h *AuthServer) getSigningKey(ctx context.Context, setName string) (crypto.Signer, string, error) {
	setName = strings.TrimSpace(setName)
	if setName == "" {
		setName = defaultJWKSetName
	}

	if signer, kid, ok := h.jwkSignCache.get(setName); ok {
		return signer, kid, nil
	}

	jwks, err := h.defaultHydraCli.GetJsonWebKeySet(ctx, setName)
	if err != nil {
		// Fall back to default set name once, then fail.
		if setName != defaultJWKSetName {
			util.Log(ctx).WithError(err).WithField("jwk_set", setName).Warn("JWK set not found, falling back to default")
			setName = defaultJWKSetName
			if signer, kid, ok := h.jwkSignCache.get(setName); ok {
				return signer, kid, nil
			}
			jwks, err = h.defaultHydraCli.GetJsonWebKeySet(ctx, setName)
		}
		if err != nil {
			return nil, "", err
		}
	}

	signer, kid, err := selectSigningKey(jwks)
	if err != nil {
		return nil, "", err
	}

	h.jwkSignCache.set(setName, signer, kid, jwkSigningCacheTTL)
	return signer, kid, nil
}
