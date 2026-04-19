// Copyright 2023-2026 Ant Investor Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE).

package fedcm

import (
	"context"
	"fmt"
	"time"
)

// RevocationTTL is the lifetime of a revocation entry; it matches the hard cap
// of the idp_session cookie so that an attacker with a leaked cookie cannot
// wait out the revocation list.
const RevocationTTL = 90 * 24 * time.Hour

// RevocationKV is the narrow cache contract used by the revocation store.
// It is satisfied by the application's existing cache implementation.
type RevocationKV interface {
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, bool, error)
}

// RevocationStore records (profile_id, client_id) pairs that must be treated
// as signed-out until their TTL elapses.
type RevocationStore struct {
	kv RevocationKV
}

// NewRevocationStore wraps a cache backend.
func NewRevocationStore(kv RevocationKV) *RevocationStore {
	return &RevocationStore{kv: kv}
}

// Revoke records (profileID, clientID) as revoked for RevocationTTL.
func (s *RevocationStore) Revoke(ctx context.Context, profileID, clientID string) error {
	if profileID == "" || clientID == "" {
		return fmt.Errorf("profileID and clientID must be non-empty")
	}
	return s.kv.Set(ctx, revocationKey(profileID, clientID), "1", RevocationTTL)
}

// IsRevoked reports whether (profileID, clientID) has been revoked.
func (s *RevocationStore) IsRevoked(ctx context.Context, profileID, clientID string) (bool, error) {
	_, ok, err := s.kv.Get(ctx, revocationKey(profileID, clientID))
	if err != nil {
		return false, err
	}
	return ok, nil
}

func revocationKey(profileID, clientID string) string {
	return "fedcm:revocation:" + profileID + ":" + clientID
}
