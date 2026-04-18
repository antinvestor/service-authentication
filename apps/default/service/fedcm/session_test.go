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

package fedcm_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/providers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/stretchr/testify/require"
)

func newTestCodec(t *testing.T) *providers.StateCodec {
	t.Helper()
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key, err := hex.DecodeString(keyHex)
	require.NoError(t, err)
	codec, err := providers.NewStateCodec(key)
	require.NoError(t, err)
	return codec
}

func TestSessionCodec_EncodeDecodeRoundtrip(t *testing.T) {
	codec := newTestCodec(t)
	sc := fedcm.NewSessionCodec(codec, "fedcm_idp_session_v1")

	now := time.Now().UTC().Truncate(time.Second)
	in := &models.IdPSession{
		Version:    models.IdPSessionCurrentVersion,
		CreatedAt:  now,
		LastActive: now,
		Entries: []models.IdPSessionEntry{{
			ProfileID:   "prof_1",
			Contact:     "a@b.com",
			ContactType: "email",
			Name:        "Alice",
			AddedAt:     now,
			LastUsedAt:  now,
			AuthMethod:  "contact_verify",
		}},
	}

	encoded, err := sc.Encode(in)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	out, err := sc.Decode(encoded)
	require.NoError(t, err)
	require.Equal(t, in.Version, out.Version)
	require.Len(t, out.Entries, 1)
	require.Equal(t, "prof_1", out.Entries[0].ProfileID)
	require.Equal(t, "email", out.Entries[0].ContactType)
}

func TestSessionCodec_Read_MissingCookieReturnsEmptySession(t *testing.T) {
	codec := newTestCodec(t)
	sc := fedcm.NewSessionCodec(codec, "fedcm_idp_session_v1")

	req := httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil)

	sess, err := sc.Read(req)
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Empty(t, sess.Entries)
}

func TestSessionCodec_Read_ExpiredCookieReturnsEmptySession(t *testing.T) {
	codec := newTestCodec(t)
	sc := fedcm.NewSessionCodec(codec, "fedcm_idp_session_v1")

	stale := &models.IdPSession{
		Version:    models.IdPSessionCurrentVersion,
		CreatedAt:  time.Now().Add(-100 * 24 * time.Hour),
		LastActive: time.Now().Add(-100 * 24 * time.Hour),
	}
	encoded, err := sc.Encode(stale)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil)
	req.AddCookie(&http.Cookie{Name: fedcm.CookieNameIdPSession, Value: encoded})

	sess, err := sc.Read(req)
	require.NoError(t, err)
	require.Empty(t, sess.Entries, "expired session should return empty entries")
}

func TestSessionCodec_Read_VersionMismatchReturnsEmptySession(t *testing.T) {
	codec := newTestCodec(t)
	sc := fedcm.NewSessionCodec(codec, "fedcm_idp_session_v1")

	future := &models.IdPSession{
		Version:    99,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}
	encoded, err := sc.Encode(future)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil)
	req.AddCookie(&http.Cookie{Name: fedcm.CookieNameIdPSession, Value: encoded})

	sess, err := sc.Read(req)
	require.NoError(t, err)
	require.Empty(t, sess.Entries)
}

func TestSessionCodec_Write_SetsHardenedAttributes(t *testing.T) {
	codec := newTestCodec(t)
	sc := fedcm.NewSessionCodec(codec, "fedcm_idp_session_v1")

	rec := httptest.NewRecorder()
	sess := &models.IdPSession{Version: models.IdPSessionCurrentVersion, CreatedAt: time.Now(), LastActive: time.Now()}
	require.NoError(t, sc.Write(rec, sess))

	result := rec.Result()
	defer result.Body.Close()
	cookies := result.Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	require.Equal(t, fedcm.CookieNameIdPSession, c.Name)
	require.True(t, c.HttpOnly)
	require.True(t, c.Secure)
	require.Equal(t, http.SameSiteNoneMode, c.SameSite)
	require.Equal(t, "/", c.Path)
}

func TestSessionCodec_Clear_ZeroesCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	sc := fedcm.NewSessionCodec(newTestCodec(t), "fedcm_idp_session_v1")
	sc.Clear(rec)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, fedcm.CookieNameIdPSession, cookies[0].Name)
	require.Equal(t, "", cookies[0].Value)
	require.Less(t, cookies[0].MaxAge, 0)
}
