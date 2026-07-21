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

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/pitabwire/util"
)

func (h *AuthServer) ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {
	ctx, cancel := context.WithTimeout(req.Context(), logoutBudget)
	defer cancel()
	log := util.Log(ctx)
	hydraCli := h.defaultHydraCli

	logoutChallenge, err := hydra.GetLogoutChallengeID(req)
	if err != nil {
		log.WithError(err).Warn("missing or invalid logout_challenge parameter")
		return err
	}

	hydraCtx, hydraCancel := context.WithTimeout(ctx, logoutHydraTimeout)
	logoutReq, err := hydraCli.GetLogoutRequest(hydraCtx, logoutChallenge)
	hydraCancel()
	if err != nil {
		return err
	}

	// FedCM cleanup is best-effort under remaining budget — never block Hydra
	// accept logout on revocation/cache blips.
	if subject := logoutReq.GetSubject(); subject != "" {
		if perr := h.purgeIdPSessionEntry(ctx, rw, req, subject); perr != nil {
			log.WithError(perr).Error("failed to purge idp_session entry on logout")
		}
		for _, clientID := range h.knownClientsForSubject(ctx, subject) {
			if h.fedcmRevocation == nil {
				break
			}
			if rerr := h.fedcmRevocation.Revoke(ctx, subject, clientID); rerr != nil {
				log.WithError(rerr).WithFields(map[string]any{
					"profile_id": subject,
					"client_id":  clientID,
				}).Warn("fedcm revocation write failed")
			}
		}
	}

	acceptCtx, acceptCancel := context.WithTimeout(ctx, logoutHydraTimeout)
	redirectUrl, err := hydraCli.AcceptLogoutRequest(acceptCtx, &hydra.AcceptLogoutRequestParams{LogoutChallenge: logoutChallenge})
	acceptCancel()
	if err != nil {
		return err
	}

	h.clearRememberMeCookie(rw)
	setLoginStatusLoggedOut(rw)

	h.emitAnalyticsEvent(ctx, req, logoutReq.GetSubject(), evtLogout, nil)

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)
	return nil
}
