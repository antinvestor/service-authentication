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

package handlers_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"buf.build/gen/go/antinvestor/authentication/connectrpc/go/authentication/v1/authenticationv1connect"
	authv1 "buf.build/gen/go/antinvestor/authentication/protocolbuffers/go/authentication/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers/loginhistory"
	"github.com/antinvestor/service-authentication/apps/default/service/sessionproof"
	"github.com/stretchr/testify/require"
)

// genesisProofClient serves the Connect handler with the given caller's
// verified claims already in the request context (what the auth interceptor
// leaves behind) and returns the generated client for it.
func genesisProofClient(t *testing.T, srv *handlers.AuthServer, caller context.Context) authenticationv1connect.AuthenticationServiceClient {
	t.Helper()
	impl := loginhistory.NewLoginHistoryServer(nil, nil)
	if srv != nil {
		impl = impl.WithGenesisProofs(srv)
	}
	path, handler := authenticationv1connect.NewAuthenticationServiceHandler(impl)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(caller))
	}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return authenticationv1connect.NewAuthenticationServiceClient(server.Client(), server.URL)
}

func TestGenesisSessionProofRPC_IssueThenVerifyAndSpend(t *testing.T) {
	srv := handlers.NewGenesisProofServerForTest(t, "device-1")
	caller := handlers.PersonContextForTest(t)
	client := genesisProofClient(t, srv, caller)
	ctx := t.Context()
	pubkeyHash := strings.Repeat("AB", 32) // upper case is normalised

	issued, err := client.IssueGenesisSessionProof(ctx, connect.NewRequest(&authv1.IssueGenesisSessionProofRequest{
		PubkeyHash: pubkeyHash, DeviceKeyId: "devkey-1",
	}))
	require.NoError(t, err)
	msg := issued.Msg
	require.NotEmpty(t, msg.GetToken())
	require.Equal(t, "gsp-k1", msg.GetKeyId())
	require.Equal(t, "ed25519", msg.GetAlgorithm())
	require.Equal(t, "stawi-genesis", msg.GetAudience())

	claims, _, err := sessionproof.Decode(msg.GetToken())
	require.NoError(t, err)
	require.Equal(t, "profile-1", claims.ProfileID)
	require.Equal(t, "device-1", claims.DeviceID)
	require.Equal(t, "login-event-1", claims.SessionID)
	require.Equal(t, strings.ToLower(pubkeyHash), claims.PubkeyHash)
	require.Equal(t, claims.Nonce, msg.GetNonce())
	require.Equal(t, claims.IssuedAt, msg.GetIssuedAt())
	require.Equal(t, claims.ExpiresAt, msg.GetExpiresAt())
	digest := sessionproof.BindingHash(claims)
	require.Equal(t, hex.EncodeToString(digest[:]), msg.GetBindingHash())

	verified, err := client.VerifyGenesisSessionProof(ctx, connect.NewRequest(&authv1.VerifyGenesisSessionProofRequest{
		Token: msg.GetToken(), ProfileId: "profile-1", DeviceId: "device-1",
		PubkeyHash: strings.ToLower(pubkeyHash), DeviceKeyId: "devkey-1", Consume: true,
	}))
	require.NoError(t, err)
	require.True(t, verified.Msg.GetValid(), verified.Msg.GetReason())
	require.Equal(t, msg.GetBindingHash(), verified.Msg.GetBindingHash())
	require.Equal(t, "profile-1", verified.Msg.GetClaims().GetProfileId())
	require.Equal(t, "devkey-1", verified.Msg.GetClaims().GetDeviceKeyId())
	require.Equal(t, msg.GetNonce(), verified.Msg.GetClaims().GetNonce())

	replay, err := client.VerifyGenesisSessionProof(ctx, connect.NewRequest(&authv1.VerifyGenesisSessionProofRequest{
		Token: msg.GetToken(), Consume: true,
	}))
	require.NoError(t, err)
	require.False(t, replay.Msg.GetValid())
	require.Contains(t, replay.Msg.GetReason(), "nonce")
	require.Nil(t, replay.Msg.GetClaims())
}

func TestGenesisSessionProofRPC_RefusalsMapToConnectCodes(t *testing.T) {
	good := strings.Repeat("ab", 32)
	cases := []struct {
		name     string
		srv      func(t *testing.T) *handlers.AuthServer
		caller   func(t *testing.T) context.Context
		hash     string
		deviceID string
		want     connect.Code
	}{
		{"malformed pubkey hash", func(t *testing.T) *handlers.AuthServer { return handlers.NewGenesisProofServerForTest(t, "device-1") },
			handlers.PersonContextForTest, "not-a-digest", "", connect.CodeInvalidArgument},
		{"no authenticated caller", func(t *testing.T) *handlers.AuthServer { return handlers.NewGenesisProofServerForTest(t, "device-1") },
			func(t *testing.T) context.Context { return t.Context() }, good, "", connect.CodeUnauthenticated},
		{"session on another device", func(t *testing.T) *handlers.AuthServer { return handlers.NewGenesisProofServerForTest(t, "device-2") },
			handlers.PersonContextForTest, good, "", connect.CodePermissionDenied},
		{"requested device is not the session device", func(t *testing.T) *handlers.AuthServer { return handlers.NewGenesisProofServerForTest(t, "device-1") },
			handlers.PersonContextForTest, good, "device-9", connect.CodePermissionDenied},
		{"proofs not enabled", func(*testing.T) *handlers.AuthServer { return nil },
			handlers.PersonContextForTest, good, "", connect.CodeUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := genesisProofClient(t, tc.srv(t), tc.caller(t))
			_, err := client.IssueGenesisSessionProof(t.Context(), connect.NewRequest(&authv1.IssueGenesisSessionProofRequest{
				PubkeyHash: tc.hash, DeviceId: tc.deviceID,
			}))
			require.Error(t, err)
			require.Equal(t, tc.want, connect.CodeOf(err), err.Error())
		})
	}
}
