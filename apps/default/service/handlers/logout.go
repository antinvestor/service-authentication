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
	"net/http"

	"github.com/antinvestor/service-authentication/apps/default/service/hydra"
	"github.com/pitabwire/util"
)

func (h *AuthServer) ShowLogoutEndpoint(rw http.ResponseWriter, req *http.Request) error {

	ctx := req.Context()

	hydraCli := h.defaultHydraCli

	logoutChallenge, err := hydra.GetLogoutChallengeID(req)
	if err != nil {
		util.Log(ctx).WithError(err).Warn("missing or invalid logout_challenge parameter")
		return err
	}

	_, err = hydraCli.GetLogoutRequest(req.Context(), logoutChallenge)
	if err != nil {
		return err
	}

	redirectUrl, err := hydraCli.AcceptLogoutRequest(req.Context(), &hydra.AcceptLogoutRequestParams{LogoutChallenge: logoutChallenge})

	if err != nil {
		return err
	}

	h.clearRememberMeCookie(rw)

	http.Redirect(rw, req, redirectUrl, http.StatusSeeOther)

	return nil
}
