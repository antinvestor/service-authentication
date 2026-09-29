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

// Package sessionproof issues and verifies the genesis session proof of
// GFOS §8.2 / P26 (platform change K9): a short-lived token signed by this
// service binding profile_id ‖ device_id ‖ pubkey_hash ‖ nonce ‖ issued_at,
// issued only inside a live authenticated session on that device.
//
// A consumer (the GFOS finance service, and through it the AccountFactory
// attestation path) verifies a proof offline with the published Ed25519
// public keys; nothing in the token is secret. The binding digest is what an
// attestation signer carries on-chain as GenesisRequest.sessionProofHash.
//
// # Wire format
//
//	token  = "GSP1" "." base64url(payload_json) "." base64url(signature)
//
// base64url is RFC 4648 §5 without padding. payload_json is the JSON object
// described by Claims. signature is Ed25519 over Binding(claims) — the
// pre-image below, never over the JSON — so a verifier reconstructs the bytes
// it checks from the parsed fields and cannot be steered by JSON formatting.
//
// # Binding pre-image
//
//	Binding = "stawi.genesis-session-proof.v1"
//	          ‖ LP(profile_id) ‖ LP(device_id) ‖ LP(pubkey_hash)
//	          ‖ LP(nonce) ‖ LP(issued_at)
//	          ‖ LP(expires_at) ‖ LP(session_id) ‖ LP(device_key_id)
//	          ‖ LP(tenant_id) ‖ LP(partition_id) ‖ LP(audience) ‖ LP(key_id)
//
// LP(s) is uvarint(len(s)) ‖ UTF-8 bytes of s — the same length-prefix rule
// the audit chain's canonical encoding uses, so no field boundary is
// ambiguous. The five fields §8.2 names come first and in its order; the
// remainder bind the proof to its lifetime, session, tenant, audience and
// signing key so none of them can be swapped. Times are RFC 3339 UTC with
// microsecond precision (TimeLayout) and the JSON carries exactly the same
// strings, so JSON and pre-image can never disagree.
//
//	BindingHash = SHA-256(Binding)
package sessionproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the token prefix and the value of Claims.Version.
const Version = "GSP1"

// BindingDomain separates these signatures from every other Ed25519
// signature the platform produces.
const BindingDomain = "stawi.genesis-session-proof.v1"

// Algorithm is the only signature algorithm defined for GSP1.
const Algorithm = "ed25519"

// TimeLayout is the encoding of every timestamp, in the token and in the
// binding pre-image alike.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

// NonceBytes is the length of the random nonce before hex encoding.
const NonceBytes = 16

// Errors a verifier returns. They are distinct so a caller can tell a replay
// from an expiry from a device mismatch without parsing strings.
var (
	ErrMalformed    = errors.New("sessionproof: token is malformed")
	ErrUnknownKey   = errors.New("sessionproof: unknown signing key")
	ErrBadSignature = errors.New("sessionproof: signature does not verify")
	ErrExpired      = errors.New("sessionproof: token has expired")
	ErrNotYetValid  = errors.New("sessionproof: token was issued in the future")
	ErrAudience     = errors.New("sessionproof: token was issued for another audience")
	ErrWrongProfile = errors.New("sessionproof: token binds another profile")
	ErrWrongDevice  = errors.New("sessionproof: token binds another device")
	ErrWrongKey     = errors.New("sessionproof: token binds another device key")
	ErrReplay       = errors.New("sessionproof: nonce has already been used")
)

// Claims is the payload of a genesis session proof. Field order here is the
// JSON field order; the signature covers Binding, not this encoding.
type Claims struct {
	// Version is the format version ("GSP1").
	Version string `json:"v"`
	// KeyID names the signing key in the published key set.
	KeyID string `json:"kid"`
	// Algorithm is always "ed25519" for GSP1.
	Algorithm string `json:"alg"`
	// ProfileID is the person the proof is about (JWT sub === profile_id).
	ProfileID string `json:"sub"`
	// DeviceID is the device the live session ran on.
	DeviceID string `json:"did"`
	// PubkeyHash is the lowercase hex hash of the device public key being
	// registered, exactly as the caller presented it at issuance. The
	// authentication service binds it; it does not interpret it.
	PubkeyHash string `json:"pkh"`
	// DeviceKeyID is the devices-service identifier of that key, when known.
	DeviceKeyID string `json:"dkid,omitempty"`
	// Nonce makes each proof single-use.
	Nonce string `json:"nonce"`
	// IssuedAt and ExpiresAt bound the lifetime (RFC 3339 UTC, microseconds).
	IssuedAt  string `json:"iat"`
	ExpiresAt string `json:"exp"`
	// SessionID is the login event the proof was issued inside.
	SessionID string `json:"sid"`
	// TenantID and PartitionID scope the proof.
	TenantID    string `json:"tid"`
	PartitionID string `json:"pid"`
	// Audience is the consumer the proof is meant for.
	Audience string `json:"aud"`
}

// Binding returns the signed pre-image (see the package comment).
func Binding(c *Claims) []byte {
	var buf bytes.Buffer
	buf.WriteString(BindingDomain)
	for _, field := range []string{
		c.ProfileID, c.DeviceID, c.PubkeyHash, c.Nonce, c.IssuedAt,
		c.ExpiresAt, c.SessionID, c.DeviceKeyID,
		c.TenantID, c.PartitionID, c.Audience, c.KeyID,
	} {
		var tmp [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(tmp[:], uint64(len(field)))
		buf.Write(tmp[:n])
		buf.WriteString(field)
	}
	return buf.Bytes()
}

// BindingHash is SHA-256 of the pre-image. Its hex form is what a consumer
// records, and its 32 bytes are what an attestation carries on-chain as
// GenesisRequest.sessionProofHash.
func BindingHash(c *Claims) [32]byte { return sha256.Sum256(Binding(c)) }

// Encode renders the wire token.
func Encode(c *Claims, signature []byte) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("sessionproof: encode claims: %w", err)
	}
	enc := base64.RawURLEncoding
	return Version + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString(signature), nil
}

// Decode parses a token without verifying it. Callers must use Verify.
func Decode(token string) (*Claims, []byte, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	const wantParts = 3
	if len(parts) != wantParts || parts[0] != Version {
		return nil, nil, fmt.Errorf("%w: expected %s.<payload>.<signature>", ErrMalformed, Version)
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	signature, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%w: signature must be %d bytes", ErrMalformed, ed25519.SignatureSize)
	}
	claims := &Claims{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err = dec.Decode(claims); err != nil {
		return nil, nil, fmt.Errorf("%w: payload is not a GSP1 claim set: %v", ErrMalformed, err)
	}
	if claims.Version != Version || claims.Algorithm != Algorithm {
		return nil, nil, fmt.Errorf("%w: unsupported version %q / algorithm %q", ErrMalformed, claims.Version, claims.Algorithm)
	}
	return claims, signature, nil
}

// NewNonce returns a fresh hex nonce.
func NewNonce() (string, error) {
	raw := make([]byte, NonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("sessionproof: nonce: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// IssueRequest is everything the issuer binds. Every field comes from the
// live session or from the caller's device registration request; none of it
// is taken on trust from an unauthenticated source.
type IssueRequest struct {
	ProfileID   string
	DeviceID    string
	PubkeyHash  string
	DeviceKeyID string
	SessionID   string
	TenantID    string
	PartitionID string
}

// Issued is a minted proof.
type Issued struct {
	Token       string
	Claims      *Claims
	BindingHash string
	ExpiresAt   time.Time
}

// Issuer mints proofs with one active key.
type Issuer struct {
	keyID    string
	private  ed25519.PrivateKey
	ttl      time.Duration
	audience string
	now      func() time.Time
}

// NewIssuer builds an issuer. ttl must be short (minutes): the proof asserts
// that a person was present, which stops being true quickly.
func NewIssuer(keyID string, private ed25519.PrivateKey, ttl time.Duration, audience string) (*Issuer, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("sessionproof: a key id is required")
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sessionproof: private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if ttl <= 0 {
		return nil, errors.New("sessionproof: a positive ttl is required")
	}
	return &Issuer{keyID: keyID, private: private, ttl: ttl, audience: audience, now: time.Now}, nil
}

// WithClock overrides the clock (tests).
func (i *Issuer) WithClock(now func() time.Time) *Issuer { i.now = now; return i }

// KeyID names the active signing key.
func (i *Issuer) KeyID() string { return i.keyID }

// PublicKey is the verifying half of the active key.
func (i *Issuer) PublicKey() ed25519.PublicKey {
	return i.private.Public().(ed25519.PublicKey)
}

// Issue mints a proof for req.
func (i *Issuer) Issue(req IssueRequest) (*Issued, error) {
	switch {
	case strings.TrimSpace(req.ProfileID) == "":
		return nil, errors.New("sessionproof: profile_id is required")
	case strings.TrimSpace(req.DeviceID) == "":
		return nil, errors.New("sessionproof: device_id is required")
	case strings.TrimSpace(req.PubkeyHash) == "":
		return nil, errors.New("sessionproof: pubkey_hash is required")
	case strings.TrimSpace(req.SessionID) == "":
		return nil, errors.New("sessionproof: session_id is required")
	}
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	issuedAt := i.now().UTC().Truncate(time.Microsecond)
	expiresAt := issuedAt.Add(i.ttl)
	claims := &Claims{
		Version: Version, KeyID: i.keyID, Algorithm: Algorithm,
		ProfileID: req.ProfileID, DeviceID: req.DeviceID, PubkeyHash: strings.ToLower(req.PubkeyHash),
		DeviceKeyID: req.DeviceKeyID, Nonce: nonce,
		IssuedAt: issuedAt.Format(TimeLayout), ExpiresAt: expiresAt.Format(TimeLayout),
		SessionID: req.SessionID, TenantID: req.TenantID, PartitionID: req.PartitionID, Audience: i.audience,
	}
	signature := ed25519.Sign(i.private, Binding(claims))
	token, err := Encode(claims, signature)
	if err != nil {
		return nil, err
	}
	digest := BindingHash(claims)
	return &Issued{Token: token, Claims: claims, BindingHash: hex.EncodeToString(digest[:]), ExpiresAt: expiresAt}, nil
}

// Expectation narrows what a proof must bind. An empty field is not checked,
// so a consumer states exactly what it knows.
type Expectation struct {
	ProfileID   string
	DeviceID    string
	PubkeyHash  string
	DeviceKeyID string
}

// KeyLookup resolves a key id to its public key. Retired keys keep resolving
// so proofs issued before a rotation stay verifiable for their short life.
type KeyLookup func(keyID string) (ed25519.PublicKey, bool)

// StaticKeys is a KeyLookup over a fixed map.
func StaticKeys(keys map[string]ed25519.PublicKey) KeyLookup {
	return func(keyID string) (ed25519.PublicKey, bool) {
		k, ok := keys[keyID]
		return k, ok
	}
}

// Verifier checks proofs against the published keys.
type Verifier struct {
	keys     KeyLookup
	audience string
	leeway   time.Duration
	now      func() time.Time
}

// DefaultLeeway absorbs clock skew between the issuer and a verifier.
const DefaultLeeway = 30 * time.Second

// NewVerifier builds a verifier. An empty audience accepts any.
func NewVerifier(keys KeyLookup, audience string) *Verifier {
	return &Verifier{keys: keys, audience: audience, leeway: DefaultLeeway, now: time.Now}
}

// WithClock overrides the clock (tests).
func (v *Verifier) WithClock(now func() time.Time) *Verifier { v.now = now; return v }

// Verify parses and checks a token and returns its claims. It checks the
// signature, the lifetime, the audience and everything expect names. Replay
// is not decided here: a nonce is single-use against a store the caller owns
// (see NonceStore).
func (v *Verifier) Verify(token string, expect Expectation) (*Claims, error) {
	claims, signature, err := Decode(token)
	if err != nil {
		return nil, err
	}
	pub, ok := v.keys(claims.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, claims.KeyID)
	}
	if !ed25519.Verify(pub, Binding(claims), signature) {
		return nil, ErrBadSignature
	}
	issuedAt, err := time.Parse(TimeLayout, claims.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: issued_at", ErrMalformed)
	}
	expiresAt, err := time.Parse(TimeLayout, claims.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: expires_at", ErrMalformed)
	}
	now := v.now().UTC()
	if now.After(expiresAt.Add(v.leeway)) {
		return nil, ErrExpired
	}
	if issuedAt.After(now.Add(v.leeway)) {
		return nil, ErrNotYetValid
	}
	if v.audience != "" && claims.Audience != v.audience {
		return nil, ErrAudience
	}
	if err = matches(expect.ProfileID, claims.ProfileID, ErrWrongProfile); err != nil {
		return nil, err
	}
	if err = matches(expect.DeviceID, claims.DeviceID, ErrWrongDevice); err != nil {
		return nil, err
	}
	if err = matches(strings.ToLower(expect.PubkeyHash), claims.PubkeyHash, ErrWrongKey); err != nil {
		return nil, err
	}
	if err = matches(expect.DeviceKeyID, claims.DeviceKeyID, ErrWrongKey); err != nil {
		return nil, err
	}
	return claims, nil
}

func matches(want, got string, mismatch error) error {
	if want == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return fmt.Errorf("%w", mismatch)
	}
	return nil
}
