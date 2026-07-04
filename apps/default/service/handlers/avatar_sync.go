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

	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"

	"github.com/antinvestor/service-authentication/apps/default/service/events"
)

// maybeEmitAvatarSync publishes an asynchronous avatar-sync event when the
// external IdP supplied a picture URL and the events manager is wired up.
// The consumer is responsible for the skip-if-already-exists check and the
// actual download/upload; this function is best-effort and never blocks the
// login response on event failure.
func (h *AuthServer) maybeEmitAvatarSync(ctx context.Context, profileID, provider, avatarURL string) {
	if avatarURL == "" || profileID == "" {
		return
	}
	if h.eventsMan == nil {
		util.Log(ctx).Debug("avatar sync event not emitted — events manager not configured")
		return
	}

	payload := data.JSONMap{
		"profile_id": profileID,
		"source_url": avatarURL,
		"provider":   provider,
	}
	if err := h.eventsMan.Emit(ctx, events.EventKeyProfileAvatarSync, payload); err != nil {
		util.Log(ctx).WithError(err).WithFields(map[string]any{
			"profile_id": profileID,
			"provider":   provider,
		}).Warn("failed to emit avatar sync event")
	}
}
