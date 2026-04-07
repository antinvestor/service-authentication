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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
)

// ChainSigner manages hash chaining and Ed25519 signing for audit entries.
// The private key signs each entry hash, and the public key allows verification
// without access to the signing key.
type ChainSigner struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewChainSigner creates a signer from an existing Ed25519 private key.
// The key must be exactly ed25519.PrivateKeySize bytes (64).
func NewChainSigner(privateKey ed25519.PrivateKey) *ChainSigner {
	return &ChainSigner{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
	}
}

// GenerateChainSigner creates a new signer with a freshly generated Ed25519 key pair.
// Use this for development/testing. In production, load the key from secure storage.
func GenerateChainSigner() (*ChainSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}
	return &ChainSigner{
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// SignEntry computes the hash chain and digital signature for an audit entry.
// It sets PreviousHash, EntryHash, and Signature on the entry.
func (cs *ChainSigner) SignEntry(entry *models.AuditEntry, previousHash string) error {
	entry.PreviousHash = previousHash
	entry.EntryHash = cs.ComputeHash(entry, previousHash)

	sig := ed25519.Sign(cs.privateKey, []byte(entry.EntryHash))
	entry.Signature = hex.EncodeToString(sig)

	return nil
}

// ComputeHash computes the SHA-256 hash of an entry's content concatenated
// with the previous entry's hash. The hash covers all auditable fields to
// ensure any modification is detectable.
func (cs *ChainSigner) ComputeHash(entry *models.AuditEntry, previousHash string) string {
	detailsJSON, _ := json.Marshal(entry.Details)
	createdAt := ""
	if !entry.CreatedAt.IsZero() {
		createdAt = entry.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z")
	}

	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		entry.ProfileID,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.Service,
		string(detailsJSON),
		entry.IPAddress,
		entry.UserAgent,
		entry.DeviceID,
		entry.TargetProfileID,
		entry.TraceID,
		createdAt,
		previousHash,
	)

	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

// VerifySignature checks that the given signature is valid for the entry hash.
func (cs *ChainSigner) VerifySignature(entryHash, signatureHex string) bool {
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(cs.publicKey, []byte(entryHash), sig)
}

// PublicKeyHex returns the hex-encoded public key for external verification.
func (cs *ChainSigner) PublicKeyHex() string {
	return hex.EncodeToString(cs.publicKey)
}

// PrivateKeyHex returns the hex-encoded private key for secure storage.
func (cs *ChainSigner) PrivateKeyHex() string {
	return hex.EncodeToString(cs.privateKey)
}

// LoadPrivateKey creates a ChainSigner from a hex-encoded Ed25519 private key.
func LoadPrivateKey(hexKey string) (*ChainSigner, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}
	return NewChainSigner(ed25519.PrivateKey(keyBytes)), nil
}
