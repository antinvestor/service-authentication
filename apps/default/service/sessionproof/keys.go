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

package sessionproof

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PublicKey is one entry of the published key set. The document served at the
// well-known path is {"keys": [...]} with these fields, the same shape the
// audit service publishes, so a consumer reuses its key-set loader.
type PublicKey struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	PublicKey string     `json:"public_key_hex"`
	ValidFrom time.Time  `json:"valid_from"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// KeySet is the published set: the active key first, then retired keys that
// still verify proofs issued before the rotation.
type KeySet struct {
	Keys []PublicKey `json:"keys"`
}

// Lookup builds a KeyLookup over the set.
func (s KeySet) Lookup() KeyLookup {
	keys := make(map[string]ed25519.PublicKey, len(s.Keys))
	for _, k := range s.Keys {
		raw, err := hex.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys[k.KeyID] = raw
	}
	return StaticKeys(keys)
}

// LoadPrivateKey resolves the active signing key from a reference:
//
//	file:///path/to/key     a file holding the key, raw or hex
//	vault://<path>#<prop>   the External Secrets projection of that Vault
//	                        property, read from mountDir/<keyID>
//
// The key is a 64-byte Ed25519 private key or a 32-byte seed. There is no
// generate-on-missing path: a process that cannot resolve its key must refuse
// to start rather than issue proofs nobody can verify.
func LoadPrivateKey(ref, keyID, mountDir string) (ed25519.PrivateKey, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("sessionproof: a signing key reference is required")
	}
	var path string
	switch {
	case strings.HasPrefix(ref, "file://"):
		path = strings.TrimPrefix(ref, "file://")
	case strings.HasPrefix(ref, "vault://"):
		if strings.TrimSpace(keyID) == "" {
			return nil, errors.New("sessionproof: a key id is required to resolve a vault reference")
		}
		path = filepath.Join(mountDir, keyID)
	default:
		return nil, fmt.Errorf("sessionproof: unsupported key reference %q (want file:// or vault://)", ref)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path comes from configuration, not a request
	if err != nil {
		return nil, fmt.Errorf("sessionproof: read signing key: %w", err)
	}
	return ParsePrivateKey(raw)
}

// ParsePrivateKey accepts a 64-byte Ed25519 private key or a 32-byte seed,
// raw or hex-encoded, with surrounding whitespace ignored.
func ParsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(string(raw))
	if decoded, derr := hex.DecodeString(trimmed); derr == nil {
		raw = decoded
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("sessionproof: key must be %d or %d bytes (raw or hex), got %d",
			ed25519.PrivateKeySize, ed25519.SeedSize, len(raw))
	}
}

// ParseRetiredKeys reads "kid:hex,kid2:hex" into published, retired keys.
// They verify but never sign.
func ParseRetiredKeys(spec string, retiredAt time.Time) ([]PublicKey, error) {
	out := []PublicKey{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		keyID, hexKey, ok := strings.Cut(item, ":")
		if !ok {
			return nil, fmt.Errorf("sessionproof: retired key %q is not <key_id>:<public_key_hex>", item)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("sessionproof: retired key %q is not a %d-byte hex public key", keyID, ed25519.PublicKeySize)
		}
		at := retiredAt
		out = append(out, PublicKey{
			KeyID: strings.TrimSpace(keyID), Algorithm: Algorithm,
			PublicKey: strings.ToLower(strings.TrimSpace(hexKey)), ValidFrom: time.Time{}, RetiredAt: &at,
		})
	}
	return out, nil
}
