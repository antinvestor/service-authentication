package handlers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/pitabwire/util"
	"github.com/rs/xid"
)

const defaultAssertionTTL = 5 * time.Minute

// defaultJWKSetName is the Hydra-managed JWK set used for signing client assertions.
const defaultJWKSetName = "hydra.openid.id-token"

//nolint:gosec // standards-defined identifier, not a credential
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// signAssertionRequest is the JSON request body for the signing endpoint.
type signAssertionRequest struct {
	ClientID      string `json:"client_id"`
	TokenEndpoint string `json:"token_endpoint"`
	Audience      string `json:"audience"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	JWKSetName    string `json:"jwk_set_name"`
}

// signAssertionResponse is the JSON response from the signing endpoint.
type signAssertionResponse struct {
	ClientAssertion     string `json:"client_assertion"`
	ClientAssertionType string `json:"client_assertion_type"`
	Algorithm           string `json:"algorithm"`
	ExpiresAt           string `json:"expires_at"`
}

// SignPrivateKeyJWTEndpoint produces a signed JWT client assertion using a
// signing key fetched from Hydra's admin JWK API. The signed assertion can
// be used by callers for private_key_jwt authentication against a token
// endpoint. Hydra verifies the assertion via its own JWKS endpoint.
func (h *AuthServer) SignPrivateKeyJWTEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	log := util.Log(ctx)

	var body signAssertionRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		log.WithError(err).Error("failed to decode sign request body")
		return writeSignError(rw, http.StatusBadRequest, "invalid request body")
	}

	clientID := strings.TrimSpace(body.ClientID)
	if clientID == "" {
		return writeSignError(rw, http.StatusBadRequest, "client_id is required")
	}

	setName := strings.TrimSpace(body.JWKSetName)
	if setName == "" {
		setName = defaultJWKSetName
	}

	jwks, err := h.defaultHydraCli.GetJsonWebKeySet(ctx, setName)
	if err != nil {
		// If the requested set doesn't exist, fall back to the default Hydra JWK set.
		if setName != defaultJWKSetName {
			log.WithError(err).WithField("jwk_set", setName).Warn("JWK set not found, falling back to default")
			setName = defaultJWKSetName
			jwks, err = h.defaultHydraCli.GetJsonWebKeySet(ctx, setName)
		}
		if err != nil {
			log.WithError(err).WithField("jwk_set", setName).Error("failed to fetch JWK set from Hydra")
			return writeSignError(rw, http.StatusBadGateway, "failed to fetch signing keys")
		}
	}

	signingKey, kid, err := selectSigningKey(jwks)
	if err != nil {
		log.WithError(err).WithField("jwk_set", setName).Error("no usable signing key in JWK set")
		return writeSignError(rw, http.StatusInternalServerError, "no usable signing key")
	}

	assertion, alg, expiresAt, err := buildSignedAssertion(signingKey, kid, clientID, &body)
	if err != nil {
		log.WithError(err).Error("failed to build signed assertion")
		return writeSignError(rw, http.StatusInternalServerError, "signing failed")
	}

	log.WithFields(map[string]any{
		"client_id": clientID,
		"jwk_set":   setName,
		"algorithm": alg,
		"kid":       kid,
	}).Info("signed private_key_jwt assertion")

	resp := signAssertionResponse{
		ClientAssertion:     assertion,
		ClientAssertionType: clientAssertionTypeJWTBearer,
		Algorithm:           alg,
		ExpiresAt:           expiresAt.UTC().Format(time.RFC3339),
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	return json.NewEncoder(rw).Encode(resp)
}

// selectSigningKey picks the first "sig"-use private key from the Hydra JWK set.
// It converts Hydra's JWK representation to a Go crypto.Signer using go-jose.
func selectSigningKey(jwks *hydraclientgo.JsonWebKeySet) (crypto.Signer, string, error) {
	if jwks == nil {
		return nil, "", errors.New("JWK set is nil")
	}

	keys := jwks.GetKeys()
	if len(keys) == 0 {
		return nil, "", errors.New("JWK set contains no keys")
	}

	for _, key := range keys {
		if key.GetUse() != "" && key.GetUse() != "sig" {
			continue
		}

		signer, err := hydraJWKToSigner(&key)
		if err != nil {
			continue
		}

		return signer, key.GetKid(), nil
	}

	return nil, "", errors.New("JWK set contains no usable signing keys")
}

// hydraJWKToSigner converts a Hydra JsonWebKey to a Go crypto.Signer by
// marshalling it to JSON and unmarshaling via go-jose, which handles
// the JWK-to-Go-key conversion (RSA, ECDSA, EdDSA).
func hydraJWKToSigner(key *hydraclientgo.JsonWebKey) (crypto.Signer, error) {
	keyJSON, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("marshal JWK: %w", err)
	}

	var joseKey jose.JSONWebKey
	if err := json.Unmarshal(keyJSON, &joseKey); err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}

	signer, ok := joseKey.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("JWK key type %T is not a crypto.Signer (may be public-only)", joseKey.Key)
	}

	return signer, nil
}

func buildSignedAssertion(
	signingKey crypto.Signer,
	kid string,
	clientID string,
	body *signAssertionRequest,
) (string, string, time.Time, error) {
	method, err := signingMethodForKey(signingKey)
	if err != nil {
		return "", "", time.Time{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(defaultAssertionTTL)

	audience := strings.TrimSpace(body.Audience)
	if audience == "" {
		audience = strings.TrimSpace(body.TokenEndpoint)
	}

	issuer := strings.TrimSpace(body.Issuer)
	if issuer == "" {
		issuer = clientID
	}

	subject := strings.TrimSpace(body.Subject)
	if subject == "" {
		subject = clientID
	}

	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		ID:        xid.New().String(),
	}

	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}

	ss, err := token.SigningString()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("build JWT signing input: %w", err)
	}

	sig, err := method.Sign(ss, signingKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign JWT: %w", err)
	}

	assertion := ss + "." + base64.RawURLEncoding.EncodeToString(sig)
	return assertion, method.Alg(), expiresAt, nil
}

func signingMethodForKey(key crypto.Signer) (jwt.SigningMethod, error) {
	if key == nil {
		return nil, errors.New("signing key is required")
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		return jwt.SigningMethodES256, nil
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T for private_key_jwt", key)
	}
}

func writeSignError(rw http.ResponseWriter, statusCode int, errMsg string) error {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	return json.NewEncoder(rw).Encode(map[string]string{"error": errMsg})
}
