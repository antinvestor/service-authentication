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

package business_test

import (
	"testing"

	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type SignerTestSuite struct {
	suite.Suite
}

func TestSignerTestSuite(t *testing.T) {
	suite.Run(t, new(SignerTestSuite))
}

func (s *SignerTestSuite) TestGenerateChainSigner() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), signer)
	assert.NotEmpty(s.T(), signer.PublicKeyHex())
	assert.NotEmpty(s.T(), signer.PrivateKeyHex())
}

func (s *SignerTestSuite) TestSignEntry_SetsHashAndSignature() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		ResourceID:   "partition-1",
		Service:      "service_tenancy",
	}

	err = signer.SignEntry(entry, "")
	require.NoError(s.T(), err)

	assert.Empty(s.T(), entry.PreviousHash)
	assert.NotEmpty(s.T(), entry.EntryHash)
	assert.NotEmpty(s.T(), entry.Signature)
	assert.Len(s.T(), entry.EntryHash, 64) // SHA-256 hex = 64 chars
}

func (s *SignerTestSuite) TestHashChaining() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry1 := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		Service:      "service_tenancy",
	}
	require.NoError(s.T(), signer.SignEntry(entry1, ""))

	entry2 := &models.AuditEntry{
		ProfileID:    "profile-2",
		Action:       "update",
		ResourceType: "tenant",
		Service:      "service_tenancy",
	}
	require.NoError(s.T(), signer.SignEntry(entry2, entry1.EntryHash))

	// Entry2's previous hash should be entry1's hash
	assert.Equal(s.T(), entry1.EntryHash, entry2.PreviousHash)
	// Hashes should be different
	assert.NotEqual(s.T(), entry1.EntryHash, entry2.EntryHash)
}

func (s *SignerTestSuite) TestVerifySignature_Valid() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "delete",
		ResourceType: "setting",
		Service:      "service_setting",
	}
	require.NoError(s.T(), signer.SignEntry(entry, ""))

	assert.True(s.T(), signer.VerifySignature(entry.EntryHash, entry.Signature))
}

func (s *SignerTestSuite) TestVerifySignature_TamperedHash() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		Service:      "service_tenancy",
	}
	require.NoError(s.T(), signer.SignEntry(entry, ""))

	// Tamper with the hash
	assert.False(s.T(), signer.VerifySignature("tampered_hash", entry.Signature))
}

func (s *SignerTestSuite) TestVerifySignature_TamperedSignature() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		Service:      "service_tenancy",
	}
	require.NoError(s.T(), signer.SignEntry(entry, ""))

	assert.False(s.T(), signer.VerifySignature(entry.EntryHash, "bad_signature_hex"))
}

func (s *SignerTestSuite) TestComputeHash_Deterministic() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		ResourceID:   "p-1",
		Service:      "service_tenancy",
		Details:      data.JSONMap{"key": "value"},
	}

	hash1 := signer.ComputeHash(entry, "prev")
	hash2 := signer.ComputeHash(entry, "prev")
	assert.Equal(s.T(), hash1, hash2)

	// Different previous hash produces different result
	hash3 := signer.ComputeHash(entry, "different")
	assert.NotEqual(s.T(), hash1, hash3)
}

func (s *SignerTestSuite) TestComputeHash_ContentChangesHash() {
	signer, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry1 := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		Service:      "service_tenancy",
	}
	entry2 := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "delete", // Different action
		ResourceType: "partition",
		Service:      "service_tenancy",
	}

	hash1 := signer.ComputeHash(entry1, "")
	hash2 := signer.ComputeHash(entry2, "")
	assert.NotEqual(s.T(), hash1, hash2)
}

func (s *SignerTestSuite) TestLoadPrivateKey_RoundTrip() {
	original, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	hexKey := original.PrivateKeyHex()
	loaded, err := business.LoadPrivateKey(hexKey)
	require.NoError(s.T(), err)

	assert.Equal(s.T(), original.PublicKeyHex(), loaded.PublicKeyHex())

	// Signatures from both should be verifiable by either
	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "test",
		ResourceType: "test",
		Service:      "test",
	}
	require.NoError(s.T(), original.SignEntry(entry, ""))
	assert.True(s.T(), loaded.VerifySignature(entry.EntryHash, entry.Signature))
}

func (s *SignerTestSuite) TestLoadPrivateKey_InvalidHex() {
	_, err := business.LoadPrivateKey("not-hex")
	assert.Error(s.T(), err)
}

func (s *SignerTestSuite) TestLoadPrivateKey_WrongSize() {
	_, err := business.LoadPrivateKey("aabbccdd")
	assert.Error(s.T(), err)
}

func (s *SignerTestSuite) TestDifferentSigners_CannotVerifyEachOther() {
	signer1, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	signer2, err := business.GenerateChainSigner()
	require.NoError(s.T(), err)

	entry := &models.AuditEntry{
		ProfileID:    "profile-1",
		Action:       "create",
		ResourceType: "partition",
		Service:      "service_tenancy",
	}
	require.NoError(s.T(), signer1.SignEntry(entry, ""))

	// Signer2 should NOT be able to verify signer1's signature
	assert.False(s.T(), signer2.VerifySignature(entry.EntryHash, entry.Signature))
}
