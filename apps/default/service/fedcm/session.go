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

// Package fedcm contains the pure logic for the FedCM identity provider:
// cookie codec, origin validation, revocation list, client branding, and the
// headless Hydra driver used by the id_assertion_endpoint.
package fedcm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
)

// CookieNameIdPSession is the browser cookie holding the encrypted IdPSession.
const CookieNameIdPSession = "idp_session"

// SessionCodec encrypts/decrypts the idp_session cookie using the application's
// shared StateCodec. The codec key identifies the payload version; rotating it
// invalidates all live cookies without changing the underlying AES key.
type SessionCodec struct {
	codec    *providers.StateCodec
	codecKey string
	now      func() time.Time
}

// NewSessionCodec constructs a SessionCodec backed by the given AES codec.
func NewSessionCodec(codec *providers.StateCodec, codecKey string) *SessionCodec {
	return &SessionCodec{codec: codec, codecKey: codecKey, now: time.Now}
}

// Encode serialises an IdPSession to the on-cookie string.
func (c *SessionCodec) Encode(s *models.IdPSession) (string, error) {
	if s == nil {
		return "", fmt.Errorf("nil session")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal idp_session: %w", err)
	}
	return c.codec.Encode(c.codecKey, string(raw))
}

// Decode parses the on-cookie string back to an IdPSession.
func (c *SessionCodec) Decode(encoded string) (*models.IdPSession, error) {
	var raw string
	if err := c.codec.Decode(c.codecKey, encoded, &raw); err != nil {
		return nil, fmt.Errorf("decrypt idp_session: %w", err)
	}
	var s models.IdPSession
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, fmt.Errorf("unmarshal idp_session: %w", err)
	}
	return &s, nil
}

// Read loads the IdPSession from the request cookie. A missing, malformed,
// version-mismatched, or expired cookie all return a fresh empty session with
// no error, so callers can treat "no session" uniformly.
func (c *SessionCodec) Read(r *http.Request) (*models.IdPSession, error) {
	empty := &models.IdPSession{Version: models.IdPSessionCurrentVersion}

	cookie, err := r.Cookie(CookieNameIdPSession)
	if err != nil {
		return empty, nil
	}
	s, err := c.Decode(cookie.Value)
	if err != nil {
		return empty, nil
	}
	if s.Version != models.IdPSessionCurrentVersion {
		return empty, nil
	}
	if s.Expired(c.now()) {
		return empty, nil
	}
	return s, nil
}

// Write sets the encrypted idp_session cookie on the response with hardened
// attributes appropriate for FedCM (SameSite=None so the browser can attach
// the cookie on cross-site FedCM calls).
func (c *SessionCodec) Write(w http.ResponseWriter, s *models.IdPSession) error {
	encoded, err := c.Encode(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieNameIdPSession,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Expires:  s.CreatedAt.Add(models.IdPSessionHardCap),
	})
	return nil
}

// Clear removes the idp_session cookie from the browser.
func (c *SessionCodec) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieNameIdPSession,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
