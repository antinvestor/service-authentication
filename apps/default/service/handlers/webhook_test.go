package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractGrantType(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected string
	}{
		{
			name:     "top-level string",
			payload:  map[string]any{"grant_type": "authorization_code"},
			expected: "authorization_code",
		},
		{
			name:     "top-level grant_types array",
			payload:  map[string]any{"grant_types": []any{"client_credentials"}},
			expected: "client_credentials",
		},
		{
			name: "request.grant_type",
			payload: map[string]any{
				"request": map[string]any{"grant_type": "refresh_token"},
			},
			expected: "refresh_token",
		},
		{
			name: "requester.grant_type",
			payload: map[string]any{
				"requester": map[string]any{"grant_type": "client_credentials"},
			},
			expected: "client_credentials",
		},
		{
			name: "request.grant_types string slice",
			payload: map[string]any{
				"request": map[string]any{"grant_types": []any{"authorization_code"}},
			},
			expected: "authorization_code",
		},
		{
			name:     "missing",
			payload:  map[string]any{"foo": "bar"},
			expected: "",
		},
		{
			name:     "empty payload",
			payload:  map[string]any{},
			expected: "",
		},
		{
			name:     "whitespace trimmed",
			payload:  map[string]any{"grant_type": "  client_credentials  "},
			expected: "client_credentials",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractGrantType(tc.payload)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractGrantedScopes(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected []string
	}{
		{
			name:     "top-level granted_scopes",
			payload:  map[string]any{"granted_scopes": []any{"openid", "offline"}},
			expected: []string{"openid", "offline"},
		},
		{
			name: "request.granted_scopes",
			payload: map[string]any{
				"request": map[string]any{"granted_scopes": []any{"system:internal"}},
			},
			expected: []string{"system:internal"},
		},
		{
			name: "requester.granted_scopes",
			payload: map[string]any{
				"requester": map[string]any{"granted_scopes": []any{"openid"}},
			},
			expected: []string{"openid"},
		},
		{
			name:     "missing",
			payload:  map[string]any{"foo": "bar"},
			expected: nil,
		},
		{
			name:     "wrong type (string instead of array)",
			payload:  map[string]any{"granted_scopes": "openid"},
			expected: nil,
		},
		{
			name:     "empty array",
			payload:  map[string]any{"granted_scopes": []any{}},
			expected: []string{},
		},
		{
			name:     "mixed types in array",
			payload:  map[string]any{"granted_scopes": []any{"openid", 42, "offline"}},
			expected: []string{"openid", "offline"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractGrantedScopes(tc.payload)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractClientID(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected string
	}{
		{
			name: "session.client_id",
			payload: map[string]any{
				"session": map[string]any{"client_id": "my-client"},
			},
			expected: "my-client",
		},
		{
			name: "request.client_id",
			payload: map[string]any{
				"request": map[string]any{"client_id": "req-client"},
			},
			expected: "req-client",
		},
		{
			name: "requester.client_id",
			payload: map[string]any{
				"requester": map[string]any{"client_id": "reqr-client"},
			},
			expected: "reqr-client",
		},
		{
			name:     "top-level client_id",
			payload:  map[string]any{"client_id": "top-client"},
			expected: "top-client",
		},
		{
			name:     "missing",
			payload:  map[string]any{},
			expected: "",
		},
		{
			name: "session takes priority over request",
			payload: map[string]any{
				"session": map[string]any{"client_id": "session-client"},
				"request": map[string]any{"client_id": "request-client"},
			},
			expected: "session-client",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractClientID(tc.payload)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractLoginEventIDFromWebhook(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected string
	}{
		{
			name: "session.access_token.session_id",
			payload: map[string]any{
				"session": map[string]any{
					"access_token": map[string]any{"session_id": "evt-123"},
				},
			},
			expected: "evt-123",
		},
		{
			name: "id_token nested ext.session_id",
			payload: map[string]any{
				"session": map[string]any{
					"id_token": map[string]any{
						"id_token_claims": map[string]any{
							"ext": map[string]any{"session_id": "evt-456"},
						},
					},
				},
			},
			expected: "evt-456",
		},
		{
			name: "session.extra.session_id",
			payload: map[string]any{
				"session": map[string]any{
					"extra": map[string]any{"session_id": "evt-789"},
				},
			},
			expected: "evt-789",
		},
		{
			name: "deep nested id_token_claims",
			payload: map[string]any{
				"session": map[string]any{
					"id_token": map[string]any{
						"id_token_claims": map[string]any{
							"ext": map[string]any{
								"id_token_claims": map[string]any{"session_id": "evt-deep"},
							},
						},
					},
				},
			},
			expected: "evt-deep",
		},
		{
			name:     "missing session",
			payload:  map[string]any{},
			expected: "",
		},
		{
			name: "empty session",
			payload: map[string]any{
				"session": map[string]any{},
			},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractLoginEventIDFromWebhook(tc.payload)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractOAuth2SessionID(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected string
	}{
		{
			name: "session.access_token.oauth2_session_id",
			payload: map[string]any{
				"session": map[string]any{
					"access_token": map[string]any{"oauth2_session_id": "hydra-sess-1"},
				},
			},
			expected: "hydra-sess-1",
		},
		{
			name: "session.id fallback",
			payload: map[string]any{
				"session": map[string]any{
					"id": "hydra-internal-id",
				},
			},
			expected: "hydra-internal-id",
		},
		{
			name: "session.extra.oauth2_session_id",
			payload: map[string]any{
				"session": map[string]any{
					"extra": map[string]any{"oauth2_session_id": "extra-sess"},
				},
			},
			expected: "extra-sess",
		},
		{
			name:     "missing",
			payload:  map[string]any{},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractOAuth2SessionID(tc.payload)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsNonUserRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    any
		expected bool
	}{
		{
			name:     "system_internal string slice",
			roles:    []string{"system_internal"},
			expected: true,
		},
		{
			name:     "system_external string slice",
			roles:    []string{"system_external"},
			expected: true,
		},
		{
			name:     "user role only",
			roles:    []string{"user"},
			expected: false,
		},
		{
			name:     "mixed with system_internal",
			roles:    []string{"user", "system_internal"},
			expected: true,
		},
		{
			name:     "system_internal any slice (JSON)",
			roles:    []any{"system_internal"},
			expected: true,
		},
		{
			name:     "system_external any slice (JSON)",
			roles:    []any{"system_external"},
			expected: true,
		},
		{
			name:     "user role any slice",
			roles:    []any{"user"},
			expected: false,
		},
		{
			name:     "nil",
			roles:    nil,
			expected: false,
		},
		{
			name:     "empty string slice",
			roles:    []string{},
			expected: false,
		},
		{
			name:     "empty any slice",
			roles:    []any{},
			expected: false,
		},
		{
			name:     "wrong type (string not slice)",
			roles:    "system_internal",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isNonUserRole(tc.roles)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSelectFinalClaims(t *testing.T) {
	tests := []struct {
		name              string
		accessTokenClaims map[string]any
		deepNested        map[string]any
		extClaims         map[string]any
		extraClaims       map[string]any
		expectedKey       string // key to check for in result to verify correct source
		expectedNil       bool
	}{
		{
			name:              "access_token takes priority",
			accessTokenClaims: map[string]any{"source": "access_token", "tenant_id": "t1"},
			deepNested:        map[string]any{"source": "deep"},
			extClaims:         map[string]any{"source": "ext", "contact_id": "c1"},
			extraClaims:       map[string]any{"source": "extra"},
			expectedKey:       "access_token",
		},
		{
			name:        "deep nested second priority",
			deepNested:  map[string]any{"source": "deep"},
			extClaims:   map[string]any{"source": "ext", "contact_id": "c1"},
			extraClaims: map[string]any{"source": "extra"},
			expectedKey: "deep",
		},
		{
			name:        "ext with contact_id third priority",
			extClaims:   map[string]any{"source": "ext", "contact_id": "c1"},
			extraClaims: map[string]any{"source": "extra"},
			expectedKey: "ext",
		},
		{
			name:        "ext without contact_id skipped",
			extClaims:   map[string]any{"source": "ext"},
			extraClaims: map[string]any{"source": "extra"},
			expectedKey: "extra",
		},
		{
			name:        "extra as last resort",
			extraClaims: map[string]any{"source": "extra"},
			expectedKey: "extra",
		},
		{
			name:        "all nil returns nil",
			expectedNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := selectFinalClaims(tc.accessTokenClaims, tc.deepNested, tc.extClaims, tc.extraClaims)
			if tc.expectedNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tc.expectedKey, result["source"])
			}
		})
	}
}

func TestBuildClaimsFromLoginEvent(t *testing.T) {
	claims := buildClaimsFromLoginEvent(
		"evt-1", "tenant-1", "part-1", "access-1",
		"contact-1", "device-1", "profile-1", "oauth2-sess-1",
	)

	assert.Equal(t, "tenant-1", claims["tenant_id"])
	assert.Equal(t, "part-1", claims["partition_id"])
	assert.Equal(t, "access-1", claims["access_id"])
	assert.Equal(t, "contact-1", claims["contact_id"])
	assert.Equal(t, "evt-1", claims["session_id"])
	assert.Equal(t, "evt-1", claims["login_event_id"])
	assert.Equal(t, "oauth2-sess-1", claims["oauth2_session_id"])
	assert.Equal(t, "device-1", claims["device_id"])
	assert.Equal(t, "profile-1", claims["profile_id"])
	assert.Equal(t, []string{"user"}, claims["roles"])
}

func TestMissingRequiredUserClaims(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		expected []string
	}{
		{
			name: "all present",
			claims: map[string]any{
				"tenant_id": "t", "partition_id": "p", "access_id": "a",
				"session_id": "s", "profile_id": "pr",
			},
			expected: []string{},
		},
		{
			name:     "all missing",
			claims:   map[string]any{},
			expected: []string{"tenant_id", "partition_id", "access_id", "session_id", "profile_id"},
		},
		{
			name: "partial",
			claims: map[string]any{
				"tenant_id": "t", "profile_id": "pr",
			},
			expected: []string{"partition_id", "access_id", "session_id"},
		},
		{
			name: "empty string values count as missing",
			claims: map[string]any{
				"tenant_id": "", "partition_id": "p", "access_id": "a",
				"session_id": "s", "profile_id": "pr",
			},
			expected: []string{"tenant_id"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := missingRequiredUserClaims(tc.claims)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestWriteTokenHookResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	claims := map[string]any{
		"tenant_id": "t1",
		"roles":     []string{"user"},
	}

	err := writeTokenHookResponse(rr, claims)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	var response map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	session, ok := response["session"].(map[string]any)
	require.True(t, ok)

	accessToken, ok := session["access_token"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "t1", accessToken["tenant_id"])

	idToken, ok := session["id_token"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "t1", idToken["tenant_id"])
}

func TestExtractSessionAccessTokenClaims(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		expected map[string]any
	}{
		{
			name: "has access_token claims",
			payload: map[string]any{
				"session": map[string]any{
					"access_token": map[string]any{
						"tenant_id": "t1",
						"roles":     []any{"system_internal"},
					},
				},
			},
			expected: map[string]any{
				"tenant_id": "t1",
				"roles":     []any{"system_internal"},
			},
		},
		{
			name:     "no session",
			payload:  map[string]any{},
			expected: nil,
		},
		{
			name: "empty access_token",
			payload: map[string]any{
				"session": map[string]any{
					"access_token": map[string]any{},
				},
			},
			expected: nil,
		},
		{
			name: "no access_token in session",
			payload: map[string]any{
				"session": map[string]any{
					"id_token": map[string]any{"sub": "user1"},
				},
			},
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractSessionAccessTokenClaims(tc.payload)
			if tc.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestClaimString(t *testing.T) {
	claims := map[string]any{
		"tenant_id": "t1",
		"empty":     "",
		"non_str":   42,
	}

	assert.Equal(t, "t1", claimString(claims, "tenant_id"))
	assert.Equal(t, "", claimString(claims, "missing_key"))
	assert.Equal(t, "", claimString(claims, "empty"))
	assert.Equal(t, "", claimString(nil, "key"))
	assert.Equal(t, "", claimString(claims, "non_str"))
}

func TestInferGrantTypeFromTokenType(t *testing.T) {
	assert.Equal(t, "refresh_token", inferGrantTypeFromTokenType("refresh-token"))
	assert.Equal(t, "refresh_token", inferGrantTypeFromTokenType("refresh_token"))
	assert.Equal(t, "refresh_token", inferGrantTypeFromTokenType("Refresh-Token"))
	assert.Equal(t, "", inferGrantTypeFromTokenType("access-token"))
	assert.Equal(t, "", inferGrantTypeFromTokenType(""))
}

func TestInferDeviceName(t *testing.T) {
	tests := []struct {
		userAgent string
		expected  string
	}{
		{"", "Unknown Client"},
		{"Dart/2.19 (dart:io)", "Mobile App (Flutter)"},
		{"Flutter", "Mobile App (Flutter)"},
		{"okhttp/4.9.3", "Mobile App (Android)"},
		{"Android SDK built for x86", "Mobile App (Android)"},
		{"CFNetwork/1399 Darwin/22.1.0", "Mobile App (iOS)"},
		{"MyApp/1.0 ios/16.1", "Mobile App (iOS)"},
		{"python-requests/2.28.1", "API Client (Python)"},
		{"Python/3.11 aiohttp/3.8.4", "API Client (Python)"},
		{"Go-http-client/1.1", "API Client (Go)"},
		{"my-golang-service/1.0", "API Client (Go)"},
		{"node-fetch/1.0", "API Client (Node)"},
		{"axios/1.4.0", "Mobile App (iOS)"}, // "axios" contains "ios" which matches first
		{"curl/7.88.1", "API Client (cURL)"},
		{"PostmanRuntime/7.32.3", "API Client (Postman)"},
		{"Googlebot/2.1", "Bot"},
		{"WebCrawler/1.0", "Bot"},
		{"SearchSpider/1.0", "Bot"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "Web Browser"},
		{"Mozilla/5.0 Chrome/120", "Web Browser"},
		{"Safari/605.1.15", "Web Browser"},
		{"Firefox/120.0", "Web Browser"},
		{"custom-api-client/1.0", "API Client"},
	}

	for _, tc := range tests {
		t.Run(tc.userAgent, func(t *testing.T) {
			result := inferDeviceName(tc.userAgent)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractLoginEventID(t *testing.T) {
	tests := []struct {
		name     string
		context  any
		expected string
	}{
		{
			name:     "valid context with login_event_id",
			context:  map[string]any{"login_event_id": "evt-123"},
			expected: "evt-123",
		},
		{
			name:     "nil context",
			context:  nil,
			expected: "",
		},
		{
			name:     "context without login_event_id",
			context:  map[string]any{"other_key": "value"},
			expected: "",
		},
		{
			name:     "context with non-string login_event_id",
			context:  map[string]any{"login_event_id": 123},
			expected: "",
		},
		{
			name:     "wrong context type",
			context:  "not a map",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractLoginEventID(tc.context)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractSubjectFromSession(t *testing.T) {
	tests := []struct {
		name         string
		idTokenWrap  map[string]any
		nestedClaims map[string]any
		expected     string
	}{
		{
			name:        "subject from id_token wrapper",
			idTokenWrap: map[string]any{"subject": "user-1"},
			expected:    "user-1",
		},
		{
			name:         "sub from nested claims",
			nestedClaims: map[string]any{"sub": "user-2"},
			expected:     "user-2",
		},
		{
			name:         "id_token takes priority over nested",
			idTokenWrap:  map[string]any{"subject": "user-1"},
			nestedClaims: map[string]any{"sub": "user-2"},
			expected:     "user-1",
		},
		{
			name:     "both nil",
			expected: "",
		},
		{
			name:        "non-string subject",
			idTokenWrap: map[string]any{"subject": 42},
			expected:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractSubjectFromSession(tc.idTokenWrap, tc.nestedClaims)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractNestedClaims(t *testing.T) {
	tests := []struct {
		name             string
		idTokenWrapper   map[string]any
		expectNested     bool
		expectExt        bool
		expectDeepNested bool
	}{
		{
			name:           "nil wrapper",
			idTokenWrapper: nil,
		},
		{
			name:           "no id_token_claims",
			idTokenWrapper: map[string]any{"other": "val"},
		},
		{
			name: "id_token_claims but no ext",
			idTokenWrapper: map[string]any{
				"id_token_claims": map[string]any{"sub": "user-1"},
			},
			expectNested: true,
		},
		{
			name: "full nesting with ext and deep",
			idTokenWrapper: map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"tenant_id":       "t1",
						"id_token_claims": map[string]any{"session_id": "s1"},
					},
				},
			},
			expectNested:     true,
			expectExt:        true,
			expectDeepNested: true,
		},
		{
			name: "ext without deep nested",
			idTokenWrapper: map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{"tenant_id": "t1"},
				},
			},
			expectNested: true,
			expectExt:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nested, ext, deep := extractNestedClaims(tc.idTokenWrapper)
			if tc.expectNested {
				assert.NotNil(t, nested)
			} else {
				assert.Nil(t, nested)
			}
			if tc.expectExt {
				assert.NotNil(t, ext)
			} else {
				assert.Nil(t, ext)
			}
			if tc.expectDeepNested {
				assert.NotNil(t, deep)
			} else {
				assert.Nil(t, deep)
			}
		})
	}
}

func TestGetMapKeys(t *testing.T) {
	assert.Nil(t, getMapKeys(nil))

	keys := getMapKeys(map[string]any{"a": 1, "b": 2})
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "a")
	assert.Contains(t, keys, "b")

	keys = getMapKeys(map[string]any{})
	assert.Empty(t, keys)
}

func TestIsInternalSystemScoped(t *testing.T) {
	assert.True(t, isInternalSystemScoped([]string{"openid", "system_int"}))
	assert.True(t, isInternalSystemScoped([]string{"system_int"}))
	assert.False(t, isInternalSystemScoped([]string{"openid", "offline"}))
	assert.False(t, isInternalSystemScoped([]string{}))
	assert.False(t, isInternalSystemScoped(nil))
}

func TestIsClientIDApiKey(t *testing.T) {
	assert.True(t, isClientIDApiKey("api_key_abc123"))
	assert.False(t, isClientIDApiKey("regular-client-id"))
	assert.False(t, isClientIDApiKey(""))
	assert.False(t, isClientIDApiKey("api_ke"))
}

func TestWriteWebhookErrorResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	claims := map[string]any{
		"roles":     []string{"system_internal"},
		"tenant_id": "t1",
	}

	err := writeTokenHookResponse(rr, claims)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	session := resp["session"].(map[string]any)
	at := session["access_token"].(map[string]any)
	it := session["id_token"].(map[string]any)

	assert.Equal(t, "t1", at["tenant_id"])
	assert.Equal(t, "t1", it["tenant_id"])
}

func TestExtractOAuth2SessionIDAllLocations(t *testing.T) {
	// Test nested id_token.id_token_claims.ext
	payload := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"oauth2_session_id": "nested-sess",
					},
				},
			},
		},
	}
	assert.Equal(t, "nested-sess", extractOAuth2SessionID(payload))

	// Test deep nested ext.id_token_claims
	payload2 := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"id_token_claims": map[string]any{
							"oauth2_session_id": "deep-sess",
						},
					},
				},
			},
		},
	}
	assert.Equal(t, "deep-sess", extractOAuth2SessionID(payload2))

	// Test id_token.oauth2_session_id directly
	payload3 := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"oauth2_session_id": "direct-id-token-sess",
			},
		},
	}
	assert.Equal(t, "direct-id-token-sess", extractOAuth2SessionID(payload3))
}
