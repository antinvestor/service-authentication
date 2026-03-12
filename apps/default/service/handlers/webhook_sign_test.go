package handlers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/stretchr/testify/suite"
)

type WebhookSignTestSuite struct {
	suite.Suite
}

// --- buildSignedAssertion ---

func (s *WebhookSignTestSuite) TestBuildSignedAssertion_RSA() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	body := &signAssertionRequest{
		ClientID:      "my-client",
		TokenEndpoint: "https://hydra.example.com/oauth2/token",
	}

	assertion, alg, expiresAt, err := buildSignedAssertion(key, "rsa-kid", "my-client", body)
	s.Require().NoError(err)
	s.Equal("RS256", alg)
	s.False(expiresAt.IsZero())

	parts := strings.Split(assertion, ".")
	s.Len(parts, 3, "JWT should have 3 parts")

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	s.Require().NoError(err)
	s.True(token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	s.Require().True(ok)
	s.Equal("my-client", claims["iss"])
	s.Equal("my-client", claims["sub"])
	s.Equal("rsa-kid", token.Header["kid"])
}

func (s *WebhookSignTestSuite) TestBuildSignedAssertion_ECDSA() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)

	body := &signAssertionRequest{
		ClientID: "ec-client",
		Audience: "https://auth.example.com",
	}

	assertion, alg, _, err := buildSignedAssertion(key, "ec-kid", "ec-client", body)
	s.Require().NoError(err)
	s.Equal("ES256", alg)

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	s.Require().NoError(err)
	s.True(token.Valid)
}

func (s *WebhookSignTestSuite) TestBuildSignedAssertion_EdDSA() {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	s.Require().NoError(err)

	body := &signAssertionRequest{
		ClientID: "ed-client",
		Audience: "https://auth.example.com",
	}

	assertion, alg, _, err := buildSignedAssertion(privKey, "", "ed-client", body)
	s.Require().NoError(err)
	s.Equal("EdDSA", alg)

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		return pubKey, nil
	})
	s.Require().NoError(err)
	s.True(token.Valid)
}

func (s *WebhookSignTestSuite) TestBuildSignedAssertion_OverrideIssuerSubject() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	body := &signAssertionRequest{
		ClientID: "my-client",
		Issuer:   "custom-issuer",
		Subject:  "custom-subject",
		Audience: "https://token.example.com",
	}

	assertion, _, _, err := buildSignedAssertion(key, "", "my-client", body)
	s.Require().NoError(err)

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	s.Require().NoError(err)

	claims, ok := token.Claims.(jwt.MapClaims)
	s.Require().True(ok)
	s.Equal("custom-issuer", claims["iss"])
	s.Equal("custom-subject", claims["sub"])
}

func (s *WebhookSignTestSuite) TestBuildSignedAssertion_DefaultsToClientID() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	body := &signAssertionRequest{ClientID: "my-client"}

	assertion, _, _, err := buildSignedAssertion(key, "", "my-client", body)
	s.Require().NoError(err)

	token, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	s.Require().NoError(err)

	claims, ok := token.Claims.(jwt.MapClaims)
	s.Require().True(ok)
	s.Equal("my-client", claims["iss"])
	s.Equal("my-client", claims["sub"])
}

// --- selectSigningKey ---

func (s *WebhookSignTestSuite) TestSelectSigningKey_RSA() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	jwks := rsaTestJWKSet(key, "test-kid", "sig")

	signer, kid, err := selectSigningKey(jwks)
	s.Require().NoError(err)
	s.Equal("test-kid", kid)
	s.NotNil(signer)

	_, ok := signer.(*rsa.PrivateKey)
	s.True(ok, "expected *rsa.PrivateKey")
}

func (s *WebhookSignTestSuite) TestSelectSigningKey_SkipsEncKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	encKey := rsaTestHydraJWK(key, "enc-kid", "enc")
	sigKey := rsaTestHydraJWK(key, "sig-kid", "sig")

	jwks := hydraclientgo.NewJsonWebKeySet()
	jwks.SetKeys([]hydraclientgo.JsonWebKey{*encKey, *sigKey})

	_, kid, err := selectSigningKey(jwks)
	s.Require().NoError(err)
	s.Equal("sig-kid", kid, "should skip enc-use key and pick sig-use key")
}

func (s *WebhookSignTestSuite) TestSelectSigningKey_AcceptsEmptyUse() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// A key with empty use should be accepted (treated as signing)
	jwk := rsaTestHydraJWK(key, "empty-use-kid", "")

	jwks := hydraclientgo.NewJsonWebKeySet()
	jwks.SetKeys([]hydraclientgo.JsonWebKey{*jwk})

	_, kid, err := selectSigningKey(jwks)
	s.Require().NoError(err)
	s.Equal("empty-use-kid", kid)
}

func (s *WebhookSignTestSuite) TestSelectSigningKey_NilSet() {
	_, _, err := selectSigningKey(nil)
	s.Error(err)
	s.Contains(err.Error(), "nil")
}

func (s *WebhookSignTestSuite) TestSelectSigningKey_EmptyKeys() {
	jwks := hydraclientgo.NewJsonWebKeySet()
	jwks.SetKeys([]hydraclientgo.JsonWebKey{})

	_, _, err := selectSigningKey(jwks)
	s.Error(err)
	s.Contains(err.Error(), "no keys")
}

// --- hydraJWKToSigner ---

func (s *WebhookSignTestSuite) TestHydraJWKToSigner_PublicOnlyFails() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)

	// Build JWK with only public components
	jwk := hydraclientgo.NewJsonWebKey("RS256", "pub-kid", "RSA", "sig")
	jwk.SetN(b64url(key.N.Bytes()))
	jwk.SetE(b64url(big.NewInt(int64(key.PublicKey.E)).Bytes()))

	_, err = hydraJWKToSigner(jwk)
	s.Error(err, "public-only JWK should fail to convert to crypto.Signer")
}

// --- signingMethodForKey ---

func (s *WebhookSignTestSuite) TestSigningMethodForKey_RSA() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m, err := signingMethodForKey(key)
	s.NoError(err)
	s.Equal("RS256", m.Alg())
}

func (s *WebhookSignTestSuite) TestSigningMethodForKey_ECDSA() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m, err := signingMethodForKey(key)
	s.NoError(err)
	s.Equal("ES256", m.Alg())
}

func (s *WebhookSignTestSuite) TestSigningMethodForKey_EdDSA() {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	m, err := signingMethodForKey(key)
	s.NoError(err)
	s.Equal("EdDSA", m.Alg())
}

func (s *WebhookSignTestSuite) TestSigningMethodForKey_NilKey() {
	_, err := signingMethodForKey(nil)
	s.Error(err)
}

// --- writeSignError ---

func (s *WebhookSignTestSuite) TestWriteSignError() {
	rr := httptest.NewRecorder()
	err := writeSignError(rr, http.StatusBadRequest, "test error")
	s.NoError(err)
	s.Equal(http.StatusBadRequest, rr.Code)

	var resp map[string]string
	s.NoError(json.Unmarshal(rr.Body.Bytes(), &resp))
	s.Equal("test error", resp["error"])
}

func TestWebhookSign(t *testing.T) {
	suite.Run(t, new(WebhookSignTestSuite))
}

// --- test helpers ---

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func rsaTestHydraJWK(key *rsa.PrivateKey, kid, use string) *hydraclientgo.JsonWebKey {
	jwk := hydraclientgo.NewJsonWebKey("RS256", kid, "RSA", use)
	jwk.SetN(b64url(key.N.Bytes()))
	jwk.SetE(b64url(big.NewInt(int64(key.PublicKey.E)).Bytes()))
	jwk.SetD(b64url(key.D.Bytes()))
	if len(key.Primes) >= 2 {
		jwk.SetP(b64url(key.Primes[0].Bytes()))
		jwk.SetQ(b64url(key.Primes[1].Bytes()))
		jwk.SetDp(b64url(key.Precomputed.Dp.Bytes()))
		jwk.SetDq(b64url(key.Precomputed.Dq.Bytes()))
		jwk.SetQi(b64url(key.Precomputed.Qinv.Bytes()))
	}
	return jwk
}

func rsaTestJWKSet(key *rsa.PrivateKey, kid, use string) *hydraclientgo.JsonWebKeySet {
	jwk := rsaTestHydraJWK(key, kid, use)
	jwks := hydraclientgo.NewJsonWebKeySet()
	jwks.SetKeys([]hydraclientgo.JsonWebKey{*jwk})
	return jwks
}
