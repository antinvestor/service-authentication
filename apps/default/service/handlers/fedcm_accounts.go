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

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/models"
)

// FedCMAccount matches the FedCM specification's account object.
type FedCMAccount struct {
	ID      string `json:"id"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name"`
	Picture string `json:"picture,omitempty"`
}

// FedCMAccountsResponse is the body returned by GET /fedcm/accounts.
type FedCMAccountsResponse struct {
	Accounts []FedCMAccount `json:"accounts"`
}

// BuildFedCMAccountsResponse maps IdPSession entries to the FedCM spec shape.
// Phone-typed contacts are embedded into the Name field for display because
// FedCM's accounts object expects an email address when present.
func BuildFedCMAccountsResponse(session *models.IdPSession) FedCMAccountsResponse {
	out := FedCMAccountsResponse{}
	if session == nil {
		return out
	}
	for _, e := range session.Entries {
		acc := FedCMAccount{
			ID:      e.ProfileID,
			Name:    e.Name,
			Picture: e.AvatarURL,
		}
		switch e.ContactType {
		case "email":
			acc.Email = e.Contact
		case "phone":
			if e.Contact != "" {
				acc.Name = fmt.Sprintf("%s (%s)", e.Name, e.Contact)
			}
		}
		out.Accounts = append(out.Accounts, acc)
	}
	return out
}

// FedCMAccountsEndpoint serves GET /fedcm/accounts.
func (h *AuthServer) FedCMAccountsEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	session, err := h.fedcmSession.Read(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(BuildFedCMAccountsResponse(session))
}
