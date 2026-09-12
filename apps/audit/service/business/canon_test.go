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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/stretchr/testify/require"
)

func fixtureEntry() *models.AuditEntry {
	at := time.Date(2026, 9, 12, 10, 30, 0, 123456789, time.UTC)
	e := &models.AuditEntry{
		ProfileID: "prof|1", Action: "create", ResourceType: "loan", ResourceID: "loan-1",
		Service: "service_loans", Details: data.JSONMap{"z": 1, "a": "b|c", "nested": map[string]any{"y": true, "x": []any{1.5, "ü"}}},
		IPAddress: "10.0.0.1", UserAgent: "ua", DeviceID: "dev", TargetProfileID: "t", TraceID: "tr",
		Seq: 7, CanonVersion: models.CanonVersionV2, EntryID: "e-1", OnBehalfOf: "obo", ActorServiceAccountID: "sa",
		OccurredAt: at, ReceivedAt: at.Add(time.Second), IntentID: "intent", PayloadHash: "ab",
		Relations: data.JSONMap{"items": []any{map[string]any{"parent_type": "profile", "child_type": "contact"}}},
	}
	e.TenantID = "tenant"
	e.PartitionID = "part"
	e.CreatedAt = at.Add(2 * time.Second)
	return e
}

// TestCanonicalV2_GoldenVectors pins the byte encoding. The same vectors are
// consumed by common/auditverify; regenerate both if canon_v2 ever changes
// (which means a new canon version, never an edit).
func TestCanonicalV2_GoldenVectors(t *testing.T) {
	e := fixtureEntry()
	canon := business.CanonicalV2(e)
	sum := sha256.Sum256(canon)

	goldenPath := filepath.Join("testdata", "canon_v2", "fixture.json")
	type golden struct {
		CanonHex  string `json:"canon_hex"`
		CanonSHA  string `json:"canon_sha256"`
		EntryHash string `json:"entry_hash_genesis"`
	}
	got := golden{
		CanonHex:  hex.EncodeToString(canon),
		CanonSHA:  hex.EncodeToString(sum[:]),
		EntryHash: business.EntryHashV2(e, ""),
	}
	raw, err := os.ReadFile(goldenPath)
	if os.IsNotExist(err) || os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
		out, _ := json.MarshalIndent(got, "", "  ")
		require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
		raw, err = out, nil
	}
	require.NoError(t, err)
	var want golden
	require.NoError(t, json.Unmarshal(raw, &want))
	require.Equal(t, want, got, "canon_v2 bytes changed; this is a new canon version, not an edit")
}

func TestCanonicalV2_PipeInFieldsIsUnambiguous(t *testing.T) {
	a := fixtureEntry()
	b := fixtureEntry()
	// Move the '|' boundary between adjacent fields; the legacy encoding
	// could not tell these apart, canon_v2 must.
	a.ProfileID, a.Action = "prof", "|create"
	b.ProfileID, b.Action = "prof|", "create"
	require.Equal(t, business.EntryHashV1(a, ""), business.EntryHashV1(b, ""), "legacy encoding collides by design")
	require.NotEqual(t, business.EntryHashV2(a, ""), business.EntryHashV2(b, ""))
}

func TestCanonicalJSON_IsKeyOrderIndependentAndCompact(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"sorted keys", map[string]any{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"nested", map[string]any{"o": map[string]any{"z": nil, "y": []any{true, "s"}}}, `{"o":{"y":[true,"s"],"z":null}}`},
		{"no html escape", map[string]any{"k": "<a&b>"}, `{"k":"<a&b>"}`},
		{"integral float", map[string]any{"n": 3.0}, `{"n":3}`},
		{"fraction", map[string]any{"n": 0.1}, `{"n":0.1}`},
		{"unicode", map[string]any{"ü": "€"}, `{"ü":"€"}`},
		{"nil", nil, `null`},
		{"jsonmap", data.JSONMap{"b": "x", "a": "y"}, `{"a":"y","b":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := business.CanonicalJSON(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
	_, err := business.CanonicalJSON(map[string]any{"n": func() float64 { var z float64; return 1 / z }()})
	require.Error(t, err, "non-finite numbers are rejected")
}

func TestEntryHashV1_MatchesLegacyPreImage(t *testing.T) {
	e := fixtureEntry()
	e.CanonVersion = models.CanonVersionLegacy
	detailsJSON, _ := json.Marshal(e.Details)
	pre := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.ProfileID, e.Action, e.ResourceType, e.ResourceID, e.Service, string(detailsJSON),
		e.IPAddress, e.UserAgent, e.DeviceID, e.TargetProfileID, e.TraceID,
		e.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z"), "prev")
	sum := sha256.Sum256([]byte(pre))
	require.Equal(t, hex.EncodeToString(sum[:]), business.EntryHashV1(e, "prev"))

	got, err := business.EntryHash(e, "prev")
	require.NoError(t, err)
	require.Equal(t, business.EntryHashV1(e, "prev"), got)
	e.CanonVersion = 9
	_, err = business.EntryHash(e, "prev")
	require.Error(t, err)
}

func TestEntryHashV2_ChainsOnPreviousHash(t *testing.T) {
	e := fixtureEntry()
	h1 := business.EntryHashV2(e, "")
	h2 := business.EntryHashV2(e, h1)
	require.Len(t, h1, 64)
	require.NotEqual(t, h1, h2)
	require.Equal(t, h2, business.EntryHashV2(e, h1), "deterministic")
}

func TestSigner_SignAndVerifyByCanonVersion(t *testing.T) {
	s, err := business.GenerateSigner("k-test")
	require.NoError(t, err)

	e := fixtureEntry()
	require.NoError(t, s.SignEntry(e, ""))
	require.Equal(t, "k-test", e.KeyID)
	require.Equal(t, int16(models.CanonVersionV2), e.CanonVersion)
	require.True(t, business.VerifyHash(s.Public(), e.EntryHash, e.Signature, models.CanonVersionV2))
	require.False(t, business.VerifyHash(s.Public(), e.EntryHash, e.Signature, models.CanonVersionLegacy), "message differs per version")
	require.False(t, business.VerifyHash(s.Public(), business.EntryHashV2(e, "x"), e.Signature, models.CanonVersionV2))
	require.False(t, business.VerifyHash(s.Public(), e.EntryHash, "zz", models.CanonVersionV2))

	// Legacy signatures were over the hex string bytes.
	legacySig, err := s.SignHash(e.EntryHash, models.CanonVersionLegacy)
	require.NoError(t, err)
	require.True(t, business.VerifyHash(s.Public(), e.EntryHash, legacySig, models.CanonVersionLegacy))

	c := &models.AuditCheckpoint{Seq: 7, EntryHash: e.EntryHash}
	c.TenantID = "tenant"
	c.CreatedAt = e.CreatedAt
	require.NoError(t, s.SignCheckpoint(c))
	require.True(t, business.VerifyHash(s.Public(), business.CheckpointHash("tenant", 7, e.EntryHash, e.CreatedAt), c.Signature, models.CanonVersionV2))
}

func TestParsePrivateKey_AcceptsSeedAndFullKeyRawOrHex(t *testing.T) {
	s, err := business.GenerateSigner("k")
	require.NoError(t, err)
	full := []byte(nil)
	// Recover the raw key bytes through a signer round-trip: derive from seed.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	fromSeed, err := business.ParsePrivateKey(seed)
	require.NoError(t, err)
	full = []byte(fromSeed)

	cases := []struct {
		name string
		in   []byte
	}{
		{"raw seed", seed},
		{"hex seed", []byte(hex.EncodeToString(seed) + "\n")},
		{"raw full", full},
		{"hex full", []byte(hex.EncodeToString(full))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, perr := business.ParsePrivateKey(tc.in)
			require.NoError(t, perr)
			require.Equal(t, fromSeed, k)
		})
	}
	_, err = business.ParsePrivateKey([]byte("short"))
	require.Error(t, err)
	_ = s
}
