package handlers

import (
	"net/http/httptest"
	"testing"

	hydraclientgo "github.com/ory/hydra-client-go/v25"
	"github.com/stretchr/testify/suite"
)

type WebhookHelpersTestSuite struct {
	suite.Suite
}

// --- extractGrantedScopes ---

func (s *WebhookHelpersTestSuite) TestExtractGrantedScopes_TopLevel() {
	payload := map[string]any{
		"granted_scopes": []any{"openid", "offline", "system_int"},
	}
	scopes := extractGrantedScopes(payload)
	s.Equal([]string{"openid", "offline", "system_int"}, scopes)
}

func (s *WebhookHelpersTestSuite) TestExtractGrantedScopes_InRequest() {
	payload := map[string]any{
		"request": map[string]any{
			"granted_scopes": []any{"openid"},
		},
	}
	s.Equal([]string{"openid"}, extractGrantedScopes(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantedScopes_InRequester() {
	payload := map[string]any{
		"requester": map[string]any{
			"granted_scopes": []any{"openid", "system_ext"},
		},
	}
	s.Equal([]string{"openid", "system_ext"}, extractGrantedScopes(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantedScopes_Nil() {
	s.Nil(extractGrantedScopes(map[string]any{}))
	s.Nil(extractGrantedScopes(map[string]any{"granted_scopes": "not-a-slice"}))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantedScopes_NonStringEntries() {
	payload := map[string]any{
		"granted_scopes": []any{"openid", 123, true, "offline"},
	}
	scopes := extractGrantedScopes(payload)
	s.Equal([]string{"openid", "offline"}, scopes)
}

// --- extractLoginEventIDFromWebhook ---

func (s *WebhookHelpersTestSuite) TestExtractLoginEventID_AccessToken() {
	payload := map[string]any{
		"session": map[string]any{
			"access_token": map[string]any{
				"session_id": "evt-123",
			},
		},
	}
	s.Equal("evt-123", extractLoginEventIDFromWebhook(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractLoginEventID_IdTokenClaims() {
	payload := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"session_id": "evt-456",
					},
				},
			},
		},
	}
	s.Equal("evt-456", extractLoginEventIDFromWebhook(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractLoginEventID_Extra() {
	payload := map[string]any{
		"session": map[string]any{
			"extra": map[string]any{
				"session_id": "evt-789",
			},
		},
	}
	s.Equal("evt-789", extractLoginEventIDFromWebhook(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractLoginEventID_Empty() {
	s.Equal("", extractLoginEventIDFromWebhook(map[string]any{}))
	s.Equal("", extractLoginEventIDFromWebhook(map[string]any{"session": "not-a-map"}))
}

// --- extractOAuth2SessionID ---

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_AccessToken() {
	payload := map[string]any{
		"session": map[string]any{
			"access_token": map[string]any{
				"oauth2_session_id": "hydra-sess-1",
			},
		},
	}
	s.Equal("hydra-sess-1", extractOAuth2SessionID(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_SessionID() {
	payload := map[string]any{
		"session": map[string]any{
			"id": "hydra-internal-id",
		},
	}
	s.Equal("hydra-internal-id", extractOAuth2SessionID(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_Empty() {
	s.Equal("", extractOAuth2SessionID(map[string]any{}))
}

// --- extractClientID ---

func (s *WebhookHelpersTestSuite) TestExtractClientID_TopLevel() {
	s.Equal("client-1", extractClientID(map[string]any{"client_id": "client-1"}))
}

func (s *WebhookHelpersTestSuite) TestExtractClientID_InSession() {
	s.Equal("client-2", extractClientID(map[string]any{
		"session": map[string]any{"client_id": "client-2"},
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractClientID_InRequest() {
	s.Equal("client-3", extractClientID(map[string]any{
		"request": map[string]any{"client_id": "client-3"},
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractClientID_InRequester() {
	s.Equal("client-4", extractClientID(map[string]any{
		"requester": map[string]any{"client_id": "client-4"},
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractClientID_Empty() {
	s.Equal("", extractClientID(map[string]any{}))
}

// --- extractGrantType ---

func (s *WebhookHelpersTestSuite) TestExtractGrantType_TopLevel() {
	s.Equal("authorization_code", extractGrantType(map[string]any{"grant_type": "authorization_code"}))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantType_InRequest() {
	s.Equal("client_credentials", extractGrantType(map[string]any{
		"request": map[string]any{"grant_type": "client_credentials"},
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantType_AsSlice() {
	s.Equal("refresh_token", extractGrantType(map[string]any{
		"grant_type": []any{"refresh_token"},
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantType_AsStringSlice() {
	s.Equal("authorization_code", extractGrantType(map[string]any{
		"grant_type": []string{"authorization_code"},
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantType_GrantTypes() {
	s.Equal("client_credentials", extractGrantType(map[string]any{
		"grant_types": "client_credentials",
	}))
}

func (s *WebhookHelpersTestSuite) TestExtractGrantType_Empty() {
	s.Equal("", extractGrantType(map[string]any{}))
}

// --- inferGrantTypeFromTokenType ---

func (s *WebhookHelpersTestSuite) TestInferGrantTypeFromTokenType() {
	s.Equal("refresh_token", inferGrantTypeFromTokenType("refresh-token"))
	s.Equal("refresh_token", inferGrantTypeFromTokenType("refresh_token"))
	s.Equal("refresh_token", inferGrantTypeFromTokenType("REFRESH-TOKEN"))
	s.Equal("", inferGrantTypeFromTokenType("access-token"))
	s.Equal("", inferGrantTypeFromTokenType(""))
}

// --- extractSubjectFromSession ---

func (s *WebhookHelpersTestSuite) TestExtractSubjectFromSession() {
	s.Equal("sub-1", extractSubjectFromSession(
		map[string]any{"subject": "sub-1"}, nil))
	s.Equal("sub-2", extractSubjectFromSession(
		nil, map[string]any{"sub": "sub-2"}))
	s.Equal("sub-1", extractSubjectFromSession(
		map[string]any{"subject": "sub-1"},
		map[string]any{"sub": "sub-2"})) // id_token takes priority
	s.Equal("", extractSubjectFromSession(nil, nil))
}

// --- extractNestedClaims ---

func (s *WebhookHelpersTestSuite) TestExtractNestedClaims_Full() {
	wrapper := map[string]any{
		"id_token_claims": map[string]any{
			"ext": map[string]any{
				"id_token_claims": map[string]any{
					"deep": "value",
				},
			},
		},
	}
	nested, ext, deep := extractNestedClaims(wrapper)
	s.NotNil(nested)
	s.NotNil(ext)
	s.NotNil(deep)
	s.Equal("value", deep["deep"])
}

func (s *WebhookHelpersTestSuite) TestExtractNestedClaims_Nil() {
	n, e, d := extractNestedClaims(nil)
	s.Nil(n)
	s.Nil(e)
	s.Nil(d)
}

// --- selectFinalClaims ---

func (s *WebhookHelpersTestSuite) TestSelectFinalClaims_Priority() {
	at := map[string]any{"from": "access_token"}
	deep := map[string]any{"from": "deep"}
	ext := map[string]any{"contact_id": "c-1", "from": "ext"}
	extra := map[string]any{"from": "extra"}

	s.Equal(at, selectFinalClaims(at, deep, ext, extra))
	s.Equal(deep, selectFinalClaims(nil, deep, ext, extra))
	s.Equal(ext, selectFinalClaims(nil, nil, ext, extra))
	s.Equal(extra, selectFinalClaims(nil, nil, nil, extra))
	s.Nil(selectFinalClaims(nil, nil, nil, nil))
}

func (s *WebhookHelpersTestSuite) TestSelectFinalClaims_ExtWithoutContactID() {
	ext := map[string]any{"other": "val"} // no contact_id
	extra := map[string]any{"from": "extra"}

	// ext without contact_id should be skipped
	s.Equal(extra, selectFinalClaims(nil, nil, ext, extra))
}

// --- writeTokenHookResponse ---

func (s *WebhookHelpersTestSuite) TestWriteTokenHookResponse() {
	rr := httptest.NewRecorder()
	claims := map[string]any{
		"tenant_id": "t-1",
		"roles":     []string{"user"},
	}
	err := writeTokenHookResponse(rr, claims)
	s.NoError(err)
	s.Equal(200, rr.Code)
	s.Contains(rr.Header().Get("Content-Type"), "application/json")
	s.Contains(rr.Body.String(), `"tenant_id":"t-1"`)
}

// --- claimString ---

func (s *WebhookHelpersTestSuite) TestClaimString() {
	claims := map[string]any{"key": "value", "num": 123}
	s.Equal("value", claimString(claims, "key"))
	s.Equal("", claimString(claims, "num"))
	s.Equal("", claimString(claims, "missing"))
	s.Equal("", claimString(nil, "key"))
}

// --- missingRequiredUserClaims ---

func (s *WebhookHelpersTestSuite) TestMissingRequiredUserClaims_Complete() {
	claims := map[string]any{
		"tenant_id":    "t",
		"partition_id": "p",
		"access_id":    "a",
		"session_id":   "s",
		"profile_id":   "pr",
	}
	s.Empty(missingRequiredUserClaims(claims))
}

func (s *WebhookHelpersTestSuite) TestMissingRequiredUserClaims_Incomplete() {
	claims := map[string]any{
		"tenant_id": "t",
	}
	missing := missingRequiredUserClaims(claims)
	s.Contains(missing, "partition_id")
	s.Contains(missing, "access_id")
	s.Contains(missing, "session_id")
	s.Contains(missing, "profile_id")
	s.NotContains(missing, "tenant_id")
}

// --- buildClaimsFromLoginEvent ---

func (s *WebhookHelpersTestSuite) TestBuildClaimsFromLoginEvent() {
	claims := buildClaimsFromLoginEvent("evt-1", "t-1", "p-1", "a-1", "c-1", "d-1", "pr-1", "os-1")
	s.Equal("evt-1", claims["session_id"])
	s.Equal("t-1", claims["tenant_id"])
	s.Equal("p-1", claims["partition_id"])
	s.Equal("a-1", claims["access_id"])
	s.Equal("c-1", claims["contact_id"])
	s.Equal("d-1", claims["device_id"])
	s.Equal("pr-1", claims["profile_id"])
	s.Equal("os-1", claims["oauth2_session_id"])
	s.Equal("evt-1", claims["login_event_id"])
}

// --- extractSessionAccessTokenClaims ---

func (s *WebhookHelpersTestSuite) TestExtractSessionAccessTokenClaims() {
	payload := map[string]any{
		"session": map[string]any{
			"access_token": map[string]any{
				"tenant_id": "t-1",
			},
		},
	}
	claims := extractSessionAccessTokenClaims(payload)
	s.Equal("t-1", claims["tenant_id"])
}

func (s *WebhookHelpersTestSuite) TestExtractSessionAccessTokenClaims_Missing() {
	s.Nil(extractSessionAccessTokenClaims(map[string]any{}))
	s.Nil(extractSessionAccessTokenClaims(map[string]any{
		"session": map[string]any{},
	}))
	s.Nil(extractSessionAccessTokenClaims(map[string]any{
		"session": map[string]any{
			"access_token": map[string]any{},
		},
	}))
}

// --- getMapKeys ---

func (s *WebhookHelpersTestSuite) TestGetMapKeys() {
	s.Nil(getMapKeys(nil))
	keys := getMapKeys(map[string]any{"a": 1, "b": 2})
	s.Len(keys, 2)
	s.Contains(keys, "a")
	s.Contains(keys, "b")
}

func (s *WebhookHelpersTestSuite) TestServiceAccountFromHydraClient() {
	client := hydraclientgo.NewOAuth2Client()
	client.SetMetadata(map[string]any{
		"tenant_id":    "tenant-1",
		"partition_id": "partition-1",
		"profile_id":   "profile-1",
		"type":         "internal",
	})

	sa, err := serviceAccountFromHydraClient(client, "client-1")
	s.Require().NoError(err)
	s.Equal("client-1", sa.GetClientId())
	s.Equal("tenant-1", sa.GetTenantId())
	s.Equal("partition-1", sa.GetPartitionId())
	s.Equal("profile-1", sa.GetProfileId())
	s.Equal("internal", sa.GetType())
}

func (s *WebhookHelpersTestSuite) TestServiceAccountFromHydraClient_MissingMetadata() {
	client := hydraclientgo.NewOAuth2Client()
	client.SetMetadata(map[string]any{
		"tenant_id": "tenant-1",
	})

	_, err := serviceAccountFromHydraClient(client, "client-1")
	s.Error(err)
	s.Contains(err.Error(), "metadata incomplete")
}

// --- extractOAuth2SessionID additional paths ---

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_IdTokenDirect() {
	payload := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"oauth2_session_id": "direct-id",
			},
		},
	}
	s.Equal("direct-id", extractOAuth2SessionID(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_Extra() {
	payload := map[string]any{
		"session": map[string]any{
			"extra": map[string]any{
				"oauth2_session_id": "extra-id",
			},
		},
	}
	s.Equal("extra-id", extractOAuth2SessionID(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_DeepNested() {
	payload := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"oauth2_session_id": "deep-id",
					},
				},
			},
		},
	}
	s.Equal("deep-id", extractOAuth2SessionID(payload))
}

func (s *WebhookHelpersTestSuite) TestExtractOAuth2SessionID_VeryDeepNested() {
	payload := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"id_token_claims": map[string]any{
							"oauth2_session_id": "very-deep-id",
						},
					},
				},
			},
		},
	}
	s.Equal("very-deep-id", extractOAuth2SessionID(payload))
}

// --- extractLoginEventID additional paths ---

func (s *WebhookHelpersTestSuite) TestExtractLoginEventID_DeepNested() {
	payload := map[string]any{
		"session": map[string]any{
			"id_token": map[string]any{
				"id_token_claims": map[string]any{
					"ext": map[string]any{
						"id_token_claims": map[string]any{
							"session_id": "deep-evt-id",
						},
					},
				},
			},
		},
	}
	s.Equal("deep-evt-id", extractLoginEventIDFromWebhook(payload))
}

func TestWebhookHelpers(t *testing.T) {
	suite.Run(t, new(WebhookHelpersTestSuite))
}

// --- getFormKeys ---

type FormHelpersTestSuite struct {
	suite.Suite
}

func (s *FormHelpersTestSuite) TestGetFormKeys_Basic() {
	values := map[string][]string{
		"email": {"test@example.com"},
		"code":  {"123456"},
	}
	keys := getFormKeys(values)
	s.Len(keys, 2)
	s.Contains(keys, "email")
	s.Contains(keys, "code")
}

func (s *FormHelpersTestSuite) TestGetFormKeys_Empty() {
	s.Empty(getFormKeys(map[string][]string{}))
}

func (s *FormHelpersTestSuite) TestGetFormKeys_Nil() {
	s.Empty(getFormKeys(nil))
}

// --- loginAuthProviderNames ---

func (s *FormHelpersTestSuite) TestLoginAuthProviderNames_Nil() {
	s.Empty(loginAuthProviderNames(nil))
}

func TestFormHelpers(t *testing.T) {
	suite.Run(t, new(FormHelpersTestSuite))
}
