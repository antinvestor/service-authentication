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

package business

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
)

// Signer signs entry and checkpoint hashes with one identified Ed25519 key.
// The private key is never exposed after construction.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// NewSigner wraps a private key under keyID.
func NewSigner(keyID string, priv ed25519.PrivateKey) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("signer: key id is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: invalid private key size %d", len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signer: private key has no ed25519 public key")
	}
	return &Signer{keyID: keyID, priv: priv, pub: pub}, nil
}

// GenerateSigner creates a signer with a fresh key. Tests only.
func GenerateSigner(keyID string) (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate key: %w", err)
	}
	return NewSigner(keyID, priv)
}

// KeyID returns the identifier recorded on everything this signer signs.
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the verifying key.
func (s *Signer) Public() ed25519.PublicKey { return s.pub }

// PublicKeyHex returns the hex-encoded public key for publication.
func (s *Signer) PublicKeyHex() string { return hex.EncodeToString(s.pub) }

// SignHash signs an entry or checkpoint hash under the given canon version
// and returns the hex signature. Version 1 signed the hex string bytes;
// version 2 signs the raw 32-byte digest.
func (s *Signer) SignHash(hashHex string, canonVersion int16) (string, error) {
	msg, err := signingMessage(hashHex, canonVersion)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(s.priv, msg)), nil
}

// VerifyHash checks sigHex over hashHex with pub under canonVersion rules.
func VerifyHash(pub ed25519.PublicKey, hashHex, sigHex string, canonVersion int16) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg, err := signingMessage(hashHex, canonVersion)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

func signingMessage(hashHex string, canonVersion int16) ([]byte, error) {
	switch canonVersion {
	case models.CanonVersionLegacy:
		return []byte(hashHex), nil
	case models.CanonVersionV2:
		raw, err := hex.DecodeString(hashHex)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("signer: hash %q is not 32-byte hex", hashHex)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("signer: unsupported canon_version %d", canonVersion)
	}
}

// SignEntry computes PreviousHash, EntryHash, KeyID and Signature for a v2
// entry. The entry must already carry Seq and all typed fields.
func (s *Signer) SignEntry(e *models.AuditEntry, previousHash string) error {
	e.CanonVersion = models.CanonVersionV2
	e.PreviousHash = previousHash
	e.KeyID = s.keyID
	e.EntryHash = EntryHashV2(e, previousHash)
	sig, err := s.SignHash(e.EntryHash, models.CanonVersionV2)
	if err != nil {
		return err
	}
	e.Signature = sig
	return nil
}

// SignCheckpoint fills Signature and KeyID for a checkpoint whose hash is
// computed from its tenant, seq, entry hash and creation time.
func (s *Signer) SignCheckpoint(c *models.AuditCheckpoint) error {
	sig, err := s.SignHash(CheckpointHash(c.TenantID, c.Seq, c.EntryHash, c.CreatedAt), models.CanonVersionV2)
	if err != nil {
		return err
	}
	c.KeyID = s.keyID
	c.Signature = sig
	return nil
}

// ParsePrivateKey accepts a 64-byte Ed25519 private key or a 32-byte seed,
// either raw or hex-encoded (surrounding whitespace ignored).
func ParsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(trimmed); err == nil {
		raw = decoded
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("signer: key must be %d or %d bytes (raw or hex), got %d",
			ed25519.PrivateKeySize, ed25519.SeedSize, len(raw))
	}
}
