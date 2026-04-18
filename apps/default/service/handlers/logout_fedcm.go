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
	"context"
	"net/http"
)

// purgeIdPSessionEntry removes the entry for subjectID from the caller's
// idp_session cookie and rewrites it.
func (h *AuthServer) purgeIdPSessionEntry(_ context.Context, w http.ResponseWriter, r *http.Request, subjectID string) error {
	if h.fedcmSession == nil {
		return nil
	}
	session, err := h.fedcmSession.Read(r)
	if err != nil {
		return err
	}
	if removed := session.Remove(subjectID); !removed {
		return nil
	}
	if len(session.Entries) == 0 {
		h.fedcmSession.Clear(w)
		return nil
	}
	return h.fedcmSession.Write(w, session)
}

// knownClientsForSubject returns the OAuth2 client IDs that this subject has
// active Hydra consent sessions for. Intentionally minimal: returns empty in
// this task (real implementation would call Hydra admin list-consent-sessions);
// the revocation list is then populated incrementally via /fedcm/disconnect.
func (h *AuthServer) knownClientsForSubject(_ context.Context, _ string) []string {
	return nil
}
