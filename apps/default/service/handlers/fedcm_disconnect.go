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
	"net/http"

	"github.com/pitabwire/util"
)

type fedcmDisconnectRequest struct {
	ClientID  string `json:"client_id"`
	AccountID string `json:"account_hint"`
}

// FedCMDisconnectEndpoint serves POST /fedcm/disconnect. It removes the given
// account from the caller's idp_session and records a revocation entry for
// (profile_id, client_id) so that any live session on other browsers is
// rejected on its next id_assertion.
func (h *AuthServer) FedCMDisconnectEndpoint(w http.ResponseWriter, r *http.Request) error {
	setFedCMCORSHeaders(w, r)

	if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	ctx := r.Context()
	log := util.Log(ctx)

	var body fedcmDisconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	if body.ClientID == "" || body.AccountID == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	session, err := h.fedcmSession.Read(r)
	if err != nil {
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}
	if _, found := session.Find(body.AccountID); !found {
		return writeFedCMError(w, http.StatusUnauthorized, "not_signed_in")
	}

	session.Remove(body.AccountID)
	if len(session.Entries) == 0 {
		h.fedcmSession.Clear(w, r)
	} else if werr := h.fedcmSession.Write(w, r, session); werr != nil {
		log.WithError(werr).Error("rewrite idp_session after disconnect")
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}

	if h.fedcmRevocation != nil {
		if rerr := h.fedcmRevocation.Revoke(ctx, body.AccountID, body.ClientID); rerr != nil {
			log.WithError(rerr).Error("write fedcm revocation list")
			return writeFedCMError(w, http.StatusInternalServerError, "server_error")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(map[string]string{"account_id": body.AccountID})
}
