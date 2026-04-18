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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/stretchr/testify/require"
)

func TestFedCMDisconnect_RejectsMissingSecFetchDest(t *testing.T) {
	h := &handlers.AuthServer{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fedcm/disconnect", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")

	require.NoError(t, h.FedCMDisconnectEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFedCMDisconnect_MalformedBodyReturns400(t *testing.T) {
	h := &handlers.AuthServer{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fedcm/disconnect", strings.NewReader(`{bad json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "webidentity")

	require.NoError(t, h.FedCMDisconnectEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
