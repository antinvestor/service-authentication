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
	AuthCodeURL(state, codeChallenge, nonce string) string

	// Completes the login after callback
	CompleteLogin(
		ctx context.Context,
		code string,
		codeVerifier string,
		nonce string,
	) (*AuthenticatedUser, error)
}

type AuthenticatedUser struct {
	Contact   string
	Name      string
	FirstName string
	LastName  string
	Raw       map[string]any
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
