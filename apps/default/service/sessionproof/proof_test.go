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

package sessionproof_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/sessionproof"
	"github.com/stretchr/testify/require"
)

const testSeed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	private, err := sessionproof.ParsePrivateKey([]byte(testSeed))
	require.NoError(t, err)
	return private
}

func fixedIssuer(t *testing.T, at time.Time) *sessionproof.Issuer {
	t.Helper()
	issuer, err := sessionproof.NewIssuer("gsp-k1", testKey(t), 5*time.Minute, "stawi-genesis")
	require.NoError(t, err)
	return issuer.WithClock(func() time.Time { return at })
}

func issueRequest() sessionproof.IssueRequest {
	return sessionproof.IssueRequest{
		ProfileID: "profile-1", DeviceID: "device-1",
		PubkeyHash:  strings.Repeat("ab", 32),
		DeviceKeyID: "devkey-1", SessionID: "login-event-1",
		TenantID: "tenant-1", PartitionID: "partition-1",
	}
}

// TestBinding_GoldenVector pins the exact bytes a consumer must reproduce.
// GFOS verifies proofs with its own implementation of this pre-image, so any
// change here is a wire break, not a refactor.
func TestBinding_GoldenVector(t *testing.T) {
	claims := &sessionproof.Claims{
		Version: sessionproof.Version, KeyID: "gsp-k1", Algorithm: sessionproof.Algorithm,
		ProfileID: "profile-1", DeviceID: "device-1", PubkeyHash: strings.Repeat("ab", 32),
		DeviceKeyID: "devkey-1", Nonce: "0123456789abcdef0123456789abcdef",
		IssuedAt: "2026-09-16T10:30:00.000000Z", ExpiresAt: "2026-09-16T10:35:00.000000Z",
		SessionID: "login-event-1", TenantID: "tenant-1", PartitionID: "partition-1", Audience: "stawi-genesis",
	}
	binding := sessionproof.Binding(claims)

	// Domain prefix, then length-prefixed fields in the documented order.
	require.True(t, strings.HasPrefix(string(binding), sessionproof.BindingDomain))
	require.Equal(t,
		"73746177692e67656e657369732d73657373696f6e2d70726f6f662e76310970726f66696c652d3108646576"+
			"6963652d31406162616261626162616261626162616261626162616261626162616261626162616261626162"+
			"6162616261626162616261626162616261626162616261626162203031323334353637383961626364656630"+
			"3132333435363738396162636465661b323032362d30392d31365431303a33303a30302e3030303030305a1b"+
			"323032362d30392d31365431303a33353a30302e3030303030305a0d6c6f67696e2d6576656e742d31086465"+
			"766b65792d310874656e616e742d310b706172746974696f6e2d310d73746177692d67656e65736973066773"+
			"702d6b31",
		hex.EncodeToString(binding))

	digest := sessionproof.BindingHash(claims)
	require.Equal(t, "f842718e6dbe316a9ada27602589845de9c2a287dec14f399b7875671ec562bd", hex.EncodeToString(digest[:]))
}

func TestIssue_BindsTheSessionAndRoundTrips(t *testing.T) {
	at := time.Date(2026, 9, 16, 10, 30, 0, 0, time.UTC)
	issuer := fixedIssuer(t, at)

	issued, err := issuer.Issue(issueRequest())
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(issued.Token, sessionproof.Version+"."))
	require.Equal(t, "2026-09-16T10:30:00.000000Z", issued.Claims.IssuedAt)
	require.Equal(t, "2026-09-16T10:35:00.000000Z", issued.Claims.ExpiresAt)
	require.Len(t, issued.Claims.Nonce, 2*sessionproof.NonceBytes)

	claims, signature, err := sessionproof.Decode(issued.Token)
	require.NoError(t, err)
	require.Equal(t, issued.Claims, claims)
	require.True(t, ed25519.Verify(issuer.PublicKey(), sessionproof.Binding(claims), signature))

	digest := sessionproof.BindingHash(claims)
	require.Equal(t, issued.BindingHash, hex.EncodeToString(digest[:]),
		"the binding hash a consumer recomputes is what the issuer reported")

	// Two proofs never share a nonce, so neither can stand in for the other.
	second, err := issuer.Issue(issueRequest())
	require.NoError(t, err)
	require.NotEqual(t, issued.Claims.Nonce, second.Claims.Nonce)
	require.NotEqual(t, issued.BindingHash, second.BindingHash)
}

func TestVerify_AcceptsAndRefuses(t *testing.T) {
	at := time.Date(2026, 9, 16, 10, 30, 0, 0, time.UTC)
	issuer := fixedIssuer(t, at)
	issued, err := issuer.Issue(issueRequest())
	require.NoError(t, err)

	keys := sessionproof.StaticKeys(map[string]ed25519.PublicKey{"gsp-k1": issuer.PublicKey()})
	verifier := sessionproof.NewVerifier(keys, "stawi-genesis").WithClock(func() time.Time { return at.Add(time.Minute) })

	expect := sessionproof.Expectation{
		ProfileID: "profile-1", DeviceID: "device-1",
		PubkeyHash: strings.Repeat("ab", 32), DeviceKeyID: "devkey-1",
	}
	claims, err := verifier.Verify(issued.Token, expect)
	require.NoError(t, err)
	require.Equal(t, "login-event-1", claims.SessionID)

	t.Run("expired", func(t *testing.T) {
		late := sessionproof.NewVerifier(keys, "stawi-genesis").WithClock(func() time.Time { return at.Add(time.Hour) })
		_, verr := late.Verify(issued.Token, expect)
		require.ErrorIs(t, verr, sessionproof.ErrExpired)
	})

	t.Run("wrong device", func(t *testing.T) {
		other := expect
		other.DeviceID = "device-2"
		_, verr := verifier.Verify(issued.Token, other)
		require.ErrorIs(t, verr, sessionproof.ErrWrongDevice)
	})

	t.Run("wrong profile", func(t *testing.T) {
		other := expect
		other.ProfileID = "profile-2"
		_, verr := verifier.Verify(issued.Token, other)
		require.ErrorIs(t, verr, sessionproof.ErrWrongProfile)
	})

	t.Run("wrong device key", func(t *testing.T) {
		other := expect
		other.PubkeyHash = strings.Repeat("cd", 32)
		_, verr := verifier.Verify(issued.Token, other)
		require.ErrorIs(t, verr, sessionproof.ErrWrongKey)
	})

	t.Run("unknown key id", func(t *testing.T) {
		empty := sessionproof.NewVerifier(sessionproof.StaticKeys(nil), "stawi-genesis").
			WithClock(func() time.Time { return at })
		_, verr := empty.Verify(issued.Token, expect)
		require.ErrorIs(t, verr, sessionproof.ErrUnknownKey)
	})

	t.Run("another audience", func(t *testing.T) {
		elsewhere := sessionproof.NewVerifier(keys, "someone-else").WithClock(func() time.Time { return at })
		_, verr := elsewhere.Verify(issued.Token, expect)
		require.ErrorIs(t, verr, sessionproof.ErrAudience)
	})

	t.Run("tampered claim", func(t *testing.T) {
		// Rewriting the device in the payload leaves the signature over the
		// original binding, so the proof stops verifying entirely.
		parts := strings.Split(issued.Token, ".")
		payload, derr := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, derr)
		var raw map[string]any
		require.NoError(t, json.Unmarshal(payload, &raw))
		raw["did"] = "device-2"
		rewritten, merr := json.Marshal(raw)
		require.NoError(t, merr)
		forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(rewritten) + "." + parts[2]
		_, verr := verifier.Verify(forged, sessionproof.Expectation{})
		require.ErrorIs(t, verr, sessionproof.ErrBadSignature)
	})

	t.Run("not a token", func(t *testing.T) {
		_, verr := verifier.Verify("GSP2.aaa.bbb", expect)
		require.ErrorIs(t, verr, sessionproof.ErrMalformed)
	})
}

func TestKeySet_LookupAndRetiredKeys(t *testing.T) {
	private := testKey(t)
	public := private.Public().(ed25519.PublicKey)
	retired, err := sessionproof.ParseRetiredKeys("gsp-k0:"+hex.EncodeToString(public), time.Now().UTC())
	require.NoError(t, err)
	require.Len(t, retired, 1)
	require.NotNil(t, retired[0].RetiredAt)

	set := sessionproof.KeySet{Keys: append([]sessionproof.PublicKey{{
		KeyID: "gsp-k1", Algorithm: sessionproof.Algorithm, PublicKey: hex.EncodeToString(public),
	}}, retired...)}
	lookup := set.Lookup()
	for _, keyID := range []string{"gsp-k1", "gsp-k0"} {
		got, ok := lookup(keyID)
		require.True(t, ok, keyID)
		require.Equal(t, public, got)
	}
	_, ok := lookup("gsp-k9")
	require.False(t, ok)

	_, err = sessionproof.ParseRetiredKeys("broken", time.Now())
	require.Error(t, err)
}

func TestIssue_RefusesIncompleteBindings(t *testing.T) {
	issuer := fixedIssuer(t, time.Now().UTC())
	for name, mutate := range map[string]func(*sessionproof.IssueRequest){
		"no profile": func(r *sessionproof.IssueRequest) { r.ProfileID = "" },
		"no device":  func(r *sessionproof.IssueRequest) { r.DeviceID = "" },
		"no pubkey":  func(r *sessionproof.IssueRequest) { r.PubkeyHash = "" },
		"no session": func(r *sessionproof.IssueRequest) { r.SessionID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			req := issueRequest()
			mutate(&req)
			_, err := issuer.Issue(req)
			require.Error(t, err)
		})
	}
}
