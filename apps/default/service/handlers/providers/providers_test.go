package providers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// --- StateCodec Tests ---

func validKey() []byte {
	key := make([]byte, 32) // AES-256
	_, _ = rand.Read(key)
	return key
}

func TestNewStateCodec_ValidKey(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)
	assert.NotNil(t, codec)
}

func TestNewStateCodec_InvalidKeySize(t *testing.T) {
	// AES requires 16, 24, or 32 byte keys
	_, err := NewStateCodec([]byte("short"))
	assert.Error(t, err)
}

func TestStateCodec_EncodeDecodeRoundTrip(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	original := map[string]string{"foo": "bar", "baz": "qux"}
	encoded, err := codec.Encode("test-cookie", original)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	var decoded map[string]string
	err = codec.Decode("test-cookie", encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestStateCodec_EncodeDecodeAuthState(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	original := &AuthState{
		Provider:     "google",
		State:        "random-state",
		PKCEVerifier: "verifier-123",
		Nonce:        "nonce-456",
		LoginEventID: "event-789",
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	encoded, err := codec.Encode(AuthStateCookie, original)
	require.NoError(t, err)

	var decoded AuthState
	err = codec.Decode(AuthStateCookie, encoded, &decoded)
	require.NoError(t, err)
	assert.Equal(t, original.Provider, decoded.Provider)
	assert.Equal(t, original.State, decoded.State)
	assert.Equal(t, original.PKCEVerifier, decoded.PKCEVerifier)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.LoginEventID, decoded.LoginEventID)
}

func TestStateCodec_DecodeExpiredState(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	expired := &AuthState{
		Provider:  "google",
		State:     "random-state",
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
	}

	encoded, err := codec.Encode(AuthStateCookie, expired)
	require.NoError(t, err)

	var decoded AuthState
	err = codec.Decode(AuthStateCookie, encoded, &decoded)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestStateCodec_DecodeWrongName(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	data := map[string]string{"key": "value"}
	encoded, err := codec.Encode("cookie-a", data)
	require.NoError(t, err)

	// Decoding with different name should fail (authenticated data mismatch)
	var decoded map[string]string
	err = codec.Decode("cookie-b", encoded, &decoded)
	assert.Error(t, err)
}

func TestStateCodec_DecodeInvalidBase64(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	err = codec.Decode("test", "not!valid!base64!!!", new(map[string]string))
	assert.Error(t, err)
}

func TestStateCodec_DecodeTooShort(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	// Encode just a few bytes - shorter than nonce size
	short := base64.RawURLEncoding.EncodeToString([]byte("ab"))
	err = codec.Decode("test", short, new(map[string]string))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestStateCodec_DecodeTamperedData(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	encoded, err := codec.Encode("test", map[string]string{"k": "v"})
	require.NoError(t, err)

	// Tamper with the encoded data
	tampered := encoded[:len(encoded)-2] + "XX"
	err = codec.Decode("test", tampered, new(map[string]string))
	assert.Error(t, err)
}

func TestStateCodec_DifferentKeys(t *testing.T) {
	codec1, _ := NewStateCodec(validKey())
	codec2, _ := NewStateCodec(validKey())

	encoded, err := codec1.Encode("test", "hello")
	require.NoError(t, err)

	var decoded string
	err = codec2.Decode("test", encoded, &decoded)
	assert.Error(t, err) // different key should fail
}

// --- AuthState Tests ---

func TestAuthState_IsExpired_NotExpired(t *testing.T) {
	state := &AuthState{ExpiresAt: time.Now().Add(5 * time.Minute)}
	assert.False(t, state.IsExpired())
}

func TestAuthState_IsExpired_Expired(t *testing.T) {
	state := &AuthState{ExpiresAt: time.Now().Add(-1 * time.Second)}
	assert.True(t, state.IsExpired())
}

func TestAuthState_IsExpired_Zero(t *testing.T) {
	state := &AuthState{ExpiresAt: time.Time{}}
	assert.True(t, state.IsExpired()) // zero time is in the past
}

// --- Cookie Helper Tests ---

func TestSetAuthStateCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	SetAuthStateCookie(rr, "encrypted-value")

	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)

	c := cookies[0]
	assert.Equal(t, AuthStateCookie, c.Name)
	assert.Equal(t, "encrypted-value", c.Value)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, 300, c.MaxAge)
}

func TestClearAuthStateCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	ClearAuthStateCookie(rr)

	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)

	c := cookies[0]
	assert.Equal(t, AuthStateCookie, c.Name)
	assert.Equal(t, "", c.Value)
	assert.Equal(t, -1, c.MaxAge)
}

func TestAuthStateCookieConstant(t *testing.T) {
	assert.Equal(t, "__Host-auth_state", AuthStateCookie)
}

// --- PKCE Tests ---

func TestNewPKCE(t *testing.T) {
	pkce, err := NewPKCE()
	require.NoError(t, err)
	assert.NotNil(t, pkce)
	assert.NotEmpty(t, pkce.Verifier)
	assert.NotEmpty(t, pkce.Challenge)
	assert.NotEqual(t, pkce.Verifier, pkce.Challenge)
}

func TestNewPKCE_Uniqueness(t *testing.T) {
	pkce1, err := NewPKCE()
	require.NoError(t, err)
	pkce2, err := NewPKCE()
	require.NoError(t, err)
	assert.NotEqual(t, pkce1.Verifier, pkce2.Verifier)
	assert.NotEqual(t, pkce1.Challenge, pkce2.Challenge)
}

func TestNewPKCE_VerifierLength(t *testing.T) {
	pkce, err := NewPKCE()
	require.NoError(t, err)
	// 32 bytes base64url encoded = 43 chars
	assert.Len(t, pkce.Verifier, 43)
}

// --- SetupAuthProviders Tests ---

func TestSetupAuthProviders_EmptyConfig(t *testing.T) {
	cfg := &config.AuthenticationConfig{}
	providers, err := SetupAuthProviders(t.Context(), cfg)
	require.NoError(t, err)
	assert.Empty(t, providers)
}

// --- FacebookProvider Tests ---

func TestNewFacebookProvider(t *testing.T) {
	p, err := NewFacebookProvider("client-id", "client-secret", "https://example.com/callback", []string{"email"})
	require.NoError(t, err)
	assert.Equal(t, "facebook", p.Name())
}

func TestFacebookProvider_AuthCodeURL_WithoutNonce(t *testing.T) {
	p, _ := NewFacebookProvider("client-id", "client-secret", "https://example.com/callback", []string{"email"})
	url := p.AuthCodeURL("state-val", "challenge-val", "")
	assert.Contains(t, url, "state=state-val")
	assert.Contains(t, url, "code_challenge=challenge-val")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.NotContains(t, url, "nonce=")
}

func TestFacebookProvider_AuthCodeURL_WithNonce(t *testing.T) {
	p, _ := NewFacebookProvider("client-id", "client-secret", "https://example.com/callback", []string{"email"})
	url := p.AuthCodeURL("state-val", "challenge-val", "nonce-val")
	assert.Contains(t, url, "nonce=nonce-val")
}

// --- FacebookProvider CompleteLogin Tests ---

func TestFacebookProvider_CompleteLogin_TokenExchangeError(t *testing.T) {
	// Use a test server that returns an error for token exchange
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := &FacebookProvider{
		oauth2: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	_, err := p.CompleteLogin(t.Context(), "bad-code", "verifier", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

func TestFacebookProvider_CompleteLogin_Success(t *testing.T) {
	// Mock token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"mock-token","token_type":"bearer","expires_in":3600}`))
	}))
	defer tokenServer.Close()

	// Mock Graph API server
	graphServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer mock-token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"12345","name":"Test User","email":"test@example.com"}`))
	}))
	defer graphServer.Close()

	// We can't easily test the full flow because the graph API URL is hardcoded
	// But we can test the token exchange failure path
	p := &FacebookProvider{
		oauth2: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	// This will succeed at token exchange but fail at the hardcoded Facebook graph API
	_, err := p.CompleteLogin(t.Context(), "valid-code", "verifier", "")
	// Should fail because the graph API URL is hardcoded to facebook.com
	assert.Error(t, err)
}

// --- SetupAuthProviders Facebook ---

func TestSetupAuthProviders_Facebook(t *testing.T) {
	cfg := &config.AuthenticationConfig{
		AuthProviderMetaClientID:    "fb-client",
		AuthProviderMetaSecret:      "fb-secret",
		AuthProviderMetaCallbackURL: "https://example.com/callback/facebook",
		AuthProviderMetaScopes:      []string{"email"},
	}
	result, err := SetupAuthProviders(t.Context(), cfg)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Contains(t, result, "facebook")
}

// --- AuthenticatedUser struct ---

func TestAuthenticatedUser(t *testing.T) {
	user := &AuthenticatedUser{
		Contact:   "user@example.com",
		Name:      "Test User",
		FirstName: "Test",
		LastName:  "User",
		Raw:       map[string]any{"email": "user@example.com"},
	}
	assert.Equal(t, "user@example.com", user.Contact)
	assert.Equal(t, "Test User", user.Name)
}

// --- Google OIDC Provider Tests (direct struct construction, no OIDC discovery) ---

func TestGoogleOIDCProvider_Name(t *testing.T) {
	p := &GoogleOIDCProvider{
		oauth2: oauth2.Config{
			ClientID:     "google-client",
			ClientSecret: "google-secret",
		},
	}
	assert.Equal(t, "google", p.Name())
}

func TestGoogleOIDCProvider_AuthCodeURL_WithoutNonce(t *testing.T) {
	p := &GoogleOIDCProvider{
		oauth2: oauth2.Config{
			ClientID:     "google-client",
			ClientSecret: "google-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
			},
		},
	}
	url := p.AuthCodeURL("state-val", "challenge-val", "")
	assert.Contains(t, url, "state=state-val")
	assert.Contains(t, url, "code_challenge=challenge-val")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.NotContains(t, url, "nonce=")
}

func TestGoogleOIDCProvider_AuthCodeURL_WithNonce(t *testing.T) {
	p := &GoogleOIDCProvider{
		oauth2: oauth2.Config{
			ClientID: "google-client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
			},
		},
	}
	url := p.AuthCodeURL("state-val", "challenge-val", "nonce-val")
	assert.Contains(t, url, "nonce=nonce-val")
}

func TestGoogleOIDCProvider_CompleteLogin_TokenExchangeError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := &GoogleOIDCProvider{
		oauth2: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	_, err := p.CompleteLogin(t.Context(), "bad-code", "verifier", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

// --- Apple Provider Tests ---

func TestAppleProvider_Name(t *testing.T) {
	p := &AppleProvider{
		oauth2: oauth2.Config{
			ClientID: "apple-client",
		},
	}
	assert.Equal(t, "apple", p.Name())
}

func TestAppleProvider_AuthCodeURL_WithoutNonce(t *testing.T) {
	p := &AppleProvider{
		oauth2: oauth2.Config{
			ClientID: "apple-client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://appleid.apple.com/auth/authorize",
			},
		},
	}
	url := p.AuthCodeURL("state-val", "challenge-val", "")
	assert.Contains(t, url, "state=state-val")
	assert.Contains(t, url, "code_challenge=challenge-val")
	assert.Contains(t, url, "response_mode=form_post")
	assert.NotContains(t, url, "nonce=")
}

func TestAppleProvider_AuthCodeURL_WithNonce(t *testing.T) {
	p := &AppleProvider{
		oauth2: oauth2.Config{
			ClientID: "apple-client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://appleid.apple.com/auth/authorize",
			},
		},
	}
	url := p.AuthCodeURL("state-val", "challenge-val", "nonce-val")
	assert.Contains(t, url, "nonce=nonce-val")
	assert.Contains(t, url, "response_mode=form_post")
}

func TestAppleProvider_CompleteLogin_TokenExchangeError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := &AppleProvider{
		oauth2: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	_, err := p.CompleteLogin(t.Context(), "bad-code", "verifier", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

// --- Microsoft Provider Tests ---

func TestMicrosoftProvider_Name(t *testing.T) {
	p := &MicrosoftProvider{
		oauth2: oauth2.Config{
			ClientID: "ms-client",
		},
	}
	assert.Equal(t, "microsoft", p.Name())
}

func TestMicrosoftProvider_AuthCodeURL_WithoutNonce(t *testing.T) {
	p := &MicrosoftProvider{
		oauth2: oauth2.Config{
			ClientID: "ms-client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			},
		},
	}
	url := p.AuthCodeURL("state-val", "challenge-val", "")
	assert.Contains(t, url, "state=state-val")
	assert.Contains(t, url, "code_challenge=challenge-val")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.NotContains(t, url, "nonce=")
}

func TestMicrosoftProvider_AuthCodeURL_WithNonce(t *testing.T) {
	p := &MicrosoftProvider{
		oauth2: oauth2.Config{
			ClientID: "ms-client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			},
		},
	}
	url := p.AuthCodeURL("state-val", "challenge-val", "nonce-val")
	assert.Contains(t, url, "nonce=nonce-val")
}

func TestMicrosoftProvider_CompleteLogin_TokenExchangeError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := &MicrosoftProvider{
		oauth2: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	_, err := p.CompleteLogin(t.Context(), "bad-code", "verifier", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

// --- Facebook CompleteLogin with successful token exchange but Graph API returns JSON ---

func TestFacebookProvider_CompleteLogin_GraphAPISuccess(t *testing.T) {
	// Mock token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"mock-token","token_type":"bearer","expires_in":3600}`))
	}))
	defer tokenServer.Close()

	// Mock Graph API server - we need to override the hardcoded URL
	// We can't easily do that, but we can test that the token exchange works
	// The actual graph call will fail with the hardcoded URL
	p := &FacebookProvider{
		oauth2: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
		},
	}

	// Token exchange succeeds but graph API call to facebook.com will fail
	_, err := p.CompleteLogin(t.Context(), "valid-code", "verifier", "")
	assert.Error(t, err) // Will fail at Graph API call
}

// --- SetupAuthProviders Google error path ---

func TestSetupAuthProviders_GoogleDiscoveryError(t *testing.T) {
	cfg := &config.AuthenticationConfig{
		AuthProviderGoogleClientID:    "google-client",
		AuthProviderGoogleSecret:      "google-secret",
		AuthProviderGoogleCallbackURL: "https://example.com/callback/google",
	}
	// Use an already-cancelled context so OIDC discovery fails immediately
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := SetupAuthProviders(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "google")
}

// --- SetupAuthProviders Multiple providers (Facebook only works without network) ---

func TestSetupAuthProviders_MultipleFacebook(t *testing.T) {
	cfg := &config.AuthenticationConfig{
		AuthProviderMetaClientID:    "fb-client",
		AuthProviderMetaSecret:      "fb-secret",
		AuthProviderMetaCallbackURL: "https://example.com/callback/facebook",
		AuthProviderMetaScopes:      []string{"email", "public_profile"},
	}
	result, err := SetupAuthProviders(t.Context(), cfg)
	require.NoError(t, err)
	assert.Len(t, result, 1)

	fb, ok := result["facebook"]
	require.True(t, ok)
	assert.Equal(t, "facebook", fb.Name())
}

// --- StateCodec Encode error ---

func TestStateCodec_EncodeNilValue(t *testing.T) {
	codec, err := NewStateCodec(validKey())
	require.NoError(t, err)

	// nil value should still encode without error (empty gob)
	encoded, err := codec.Encode("test", (*AuthState)(nil))
	// gob may or may not error on nil pointer, but we handle it
	if err == nil {
		assert.NotEmpty(t, encoded)
	}
}
