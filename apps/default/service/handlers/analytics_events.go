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

	"github.com/pitabwire/util"

	"github.com/antinvestor/service-authentication/apps/default/service/telemetry"
	"github.com/antinvestor/service-authentication/apps/default/utils"
)

// Event name constants. Centralised so client-side dashboards built against
// these strings don't drift away from emitter sites — if you rename one of
// these, grep all callsites and update the PostHog dashboard at the same
// time.
const (
	evtLoginEventCreated  = "login_event_created"
	evtLoginCompleted     = "login_completed"
	evtLoginFailed        = "login_failed"
	evtConsentGranted     = "consent_granted"
	evtLogout             = "logout"
	evtFedCMGoogleAttempt = "fedcm_google_attempt"
	evtFedCMGoogleSuccess = "fedcm_google_success"
	evtFedCMGoogleFailed  = "fedcm_google_failed"
	evtFedCMSelfAttempt   = "fedcm_self_attempt"
	evtFedCMSelfSuccess   = "fedcm_self_success"
	evtFedCMSelfFailed    = "fedcm_self_failed"
)

// analyticsDistinctID picks the right PostHog distinct ID for an event. Use
// the authenticated profile ID when we have one; otherwise the device
// session ID so events from the same browser pre-login cluster onto a single
// timeline. The session cookie is per-browser-per-30-minutes so this gives
// useful pre-login funnels.
func analyticsDistinctID(ctx context.Context, profileID string) string {
	if profileID != "" {
		return profileID
	}
	if sid := utils.SessionIDFromContext(ctx); sid != "" {
		return sid
	}
	return telemetry.AnonymousDistinctID
}

// emitAnalyticsEvent enqueues an event on the PostHog client with the
// standard set of properties attached. Never blocks the request thread.
func (h *AuthServer) emitAnalyticsEvent(ctx context.Context, r *http.Request, profileID, event string, extra map[string]any) {
	if h == nil || h.analytics == nil {
		return
	}
	props := map[string]any{}
	for k, v := range extra {
		if v != nil {
			props[k] = v
		}
	}
	if r != nil {
		props["$ip"] = util.GetIP(r)
		props["$current_url"] = r.URL.String()
		if ua := r.UserAgent(); ua != "" {
			props["$user_agent"] = ua
		}
	}
	h.analytics.Capture(ctx, analyticsDistinctID(ctx, profileID), event, props)
}

// emitLoginCompleted is the canonical event for "a user just successfully
// authenticated". It aliases the pre-login session ID to the profile ID so
// the funnel events emitted while anonymous show up on the same person.
func (h *AuthServer) emitLoginCompleted(ctx context.Context, r *http.Request, profileID, method, clientID string) {
	if h == nil || h.analytics == nil {
		return
	}
	if sid := utils.SessionIDFromContext(ctx); sid != "" && profileID != "" && sid != profileID {
		h.analytics.Alias(ctx, sid, profileID)
	}
	h.emitAnalyticsEvent(ctx, r, profileID, evtLoginCompleted, map[string]any{
		"method":    method,
		"client_id": clientID,
	})
}
