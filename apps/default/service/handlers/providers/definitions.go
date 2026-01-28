package providers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type AuthProvider interface {
	Name() string

	// Builds the authorization redirect URL
	AuthCodeURL(state, codeChallenge string) string

	// Completes the login after callback
	CompleteLogin(
		ctx context.Context,
		code string,
		codeVerifier string,
	) (*AuthenticatedUser, error)
}

type AuthenticatedUser struct {
	Contact string
	Name    string
	FirstName    string
	LastName    string
	Raw     map[string]any
}

type PKCE struct {
	Verifier  string
	Challenge string
}

func NewPKCE() (*PKCE, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, err
	}

	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCE{
		Verifier:  verifier,
		Challenge: challenge,
	}, nil
}
