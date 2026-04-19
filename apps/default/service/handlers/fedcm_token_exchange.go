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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

type fedcmTokenExchangeRequest struct {
	IDToken string `json:"id_token"`
}

type fedcmTokenExchangeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// FedCMTokenExchangeEndpoint serves POST /fedcm/token-exchange. It consumes
// the one-shot cache entry placed by /fedcm/id-assertion and returns the
// access+refresh token pair exactly once.
func (h *AuthServer) FedCMTokenExchangeEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Body == nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	var body fedcmTokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}
	if body.IDToken == "" {
		return writeFedCMError(w, http.StatusBadRequest, "invalid_request")
	}

	ctx := r.Context()
	sum := sha256.Sum256([]byte(body.IDToken))
	key := "fedcm:exchange:" + hex.EncodeToString(sum[:])

	c, err := h.fedcmExchangeCache()
	if err != nil {
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}
	raw, ok, err := c.Get(ctx, key)
	if err != nil || !ok {
		return writeFedCMError(w, http.StatusUnauthorized, "invalid_token")
	}
	// One-shot: delete immediately.
	_ = c.Delete(ctx, key)

	var stash struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(raw), &stash); err != nil {
		return writeFedCMError(w, http.StatusInternalServerError, "server_error")
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(fedcmTokenExchangeResponse{
		AccessToken:  stash.AccessToken,
		RefreshToken: stash.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    stash.ExpiresIn,
	})
}
