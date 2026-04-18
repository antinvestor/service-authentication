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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/antinvestor/service-authentication/apps/default/service/fedcm"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/stretchr/testify/require"
)

func TestClientMetadataResponse_ShapeAndContent(t *testing.T) {
	body := handlers.BuildClientMetadataResponse(fedcm.Branding{
		PrivacyPolicyURL:  "https://app/priv",
		TermsOfServiceURL: "https://app/tos",
		IconURL:           "https://app/icon.png",
		BackgroundColor:   "#112233",
	})

	require.Equal(t, "https://app/priv", body["privacy_policy_url"])
	require.Equal(t, "https://app/tos", body["terms_of_service_url"])
	require.Equal(t, "https://app/icon.png", body["icon_url"])
	require.Equal(t, "#112233", body["background_colour"])
}

func TestFedCMClientMetadataEndpoint_RejectsMissingSecFetchDest(t *testing.T) {
	h := &handlers.AuthServer{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/fedcm/client_metadata?client_id=client_A", nil)

	require.NoError(t, h.FedCMClientMetadataEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFedCMClientMetadataEndpoint_RejectsMissingClientID(t *testing.T) {
	h := &handlers.AuthServer{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/fedcm/client_metadata", nil)
	req.Header.Set("Sec-Fetch-Dest", "webidentity")

	require.NoError(t, h.FedCMClientMetadataEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "invalid_request", body["error"])
}
