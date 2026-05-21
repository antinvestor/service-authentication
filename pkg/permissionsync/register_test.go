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

package permissionsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister_NoEnv(t *testing.T) {
	t.Setenv(EnvVar, "")
	sd := tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService")
	require.NotNil(t, sd)
	assert.NoError(t, Register(context.Background(), sd))
}

func TestRegister_PostsManifest(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(body, &received))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv(EnvVar, server.URL)
	sd := tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService")
	require.NotNil(t, sd)

	require.NoError(t, Register(context.Background(), sd))
	require.NotNil(t, received)
	assert.NotEmpty(t, received["namespace"], "namespace must be present in posted manifest")
	assert.NotNil(t, received["permissions"], "permissions list must be present")
	assert.NotNil(t, received["role_bindings"], "role_bindings must be present")
	assert.NotNil(t, received["registered_at"], "registered_at must be present")
}

func TestRegister_PropagatesNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv(EnvVar, server.URL)
	sd := tenancyv1.File_tenancy_v1_tenancy_proto.Services().ByName("TenancyService")
	require.NotNil(t, sd)

	err := Register(context.Background(), sd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}
