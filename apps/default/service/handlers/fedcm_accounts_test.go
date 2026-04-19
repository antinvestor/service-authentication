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
	"testing"
	"time"

	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/stretchr/testify/require"
)

func TestBuildFedCMAccountsResponse_EmailContactMapsToEmailField(t *testing.T) {
	session := &models.IdPSession{
		Version: models.IdPSessionCurrentVersion,
		Entries: []models.IdPSessionEntry{{
			ProfileID:   "prof_1",
			Contact:     "alice@example.com",
			ContactType: "email",
			Name:        "Alice",
			AvatarURL:   "https://cdn/a.png",
			LastUsedAt:  time.Now(),
		}},
	}

	resp := handlers.BuildFedCMAccountsResponse(session)

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, "prof_1", resp.Accounts[0].ID)
	require.Equal(t, "alice@example.com", resp.Accounts[0].Email)
	require.Equal(t, "Alice", resp.Accounts[0].Name)
	require.Equal(t, "https://cdn/a.png", resp.Accounts[0].Picture)
}

func TestBuildFedCMAccountsResponse_PhoneContactOmitsEmail(t *testing.T) {
	session := &models.IdPSession{
		Entries: []models.IdPSessionEntry{{
			ProfileID:   "prof_2",
			Contact:     "+254700000000",
			ContactType: "phone",
			Name:        "Bob",
			LastUsedAt:  time.Now(),
		}},
	}

	resp := handlers.BuildFedCMAccountsResponse(session)

	require.Len(t, resp.Accounts, 1)
	require.Equal(t, "", resp.Accounts[0].Email)
	require.Equal(t, "Bob (+254700000000)", resp.Accounts[0].Name)
}

func TestBuildFedCMAccountsResponse_EmptySessionReturnsEmptyList(t *testing.T) {
	resp := handlers.BuildFedCMAccountsResponse(&models.IdPSession{})
	require.Empty(t, resp.Accounts)
}

func TestFedCMAccountsEndpoint_RejectsMissingSecFetchDest(t *testing.T) {
	h := &handlers.AuthServer{}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil)
	err := h.FedCMAccountsEndpoint(rec, req)

	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
