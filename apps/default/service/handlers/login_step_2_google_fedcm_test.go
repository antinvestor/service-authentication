// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/antinvestor/service-authentication/apps/default/service/telemetry"
)

// These tests cover the input-validation perimeter of the Google FedCM
// completion endpoint. Anything that depends on a real LoginEvent cache or
// Hydra client lives in the integration suite (apps/default/tests/fedcm)
// — here we lock in the cheap-to-test refusals that protect the deeper
// flow from ever being reached with malformed or hostile input.

func newGoogleFedCMRequest(t *testing.T, body any, applyHeaders func(*http.Request)) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(http.MethodPost, "/s/social/google/fedcm-complete", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "https://accounts.stawi.org")
	req.RemoteAddr = "203.0.113.7:54321"
	if applyHeaders != nil {
		applyHeaders(req)
	}
	return req
}

// fedcmEndpointHarness returns the minimal AuthServer surface needed to
// exercise the endpoint's early-return paths. Steady-state assumes:
//   - no rate-limit cache → CheckLoginRateLimit auto-allows
//   - noop analytics (telemetry.New with empty key) so emit calls don't panic
//   - no LoginEventRepo so any test that needs the cache lookup would
//     crash; tests must short-circuit before that.
func fedcmEndpointHarness() *AuthServer {
	return &AuthServer{
		analytics: telemetry.New(context.Background(), "", ""),
	}
}

func TestFedCMGoogleComplete_RejectsCrossSiteFetch(t *testing.T) {
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t,
		map[string]any{"login_event_id": "le1", "id_token": "tok"},
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusForbidden, rec.Code,
		"cross-site Sec-Fetch-Site must be refused before any token work")

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "invalid_request", body["error"])
}

func TestFedCMGoogleComplete_RejectsSameSite(t *testing.T) {
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t,
		map[string]any{"login_event_id": "le1", "id_token": "tok"},
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") })

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusForbidden, rec.Code,
		"same-site (sibling subdomain) must still be refused — only same-origin is accepted")
}

func TestFedCMGoogleComplete_AcceptsMissingSecFetchSite(t *testing.T) {
	// Some browsers + curl-based health checks don't send Sec-Fetch-Site.
	// Our handler only rejects an explicitly non-same-origin value; an
	// absent header proceeds to the next validation step.
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t, nil, func(r *http.Request) {
		r.Header.Del("Sec-Fetch-Site")
		// Empty body so it fails at JSON decode, not at Sec-Fetch.
	})

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"missing Sec-Fetch-Site must fall through to body validation, not be refused outright")
}

func TestFedCMGoogleComplete_RejectsMalformedJSON(t *testing.T) {
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/s/social/google/fedcm-complete",
		strings.NewReader("{not-json"))
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFedCMGoogleComplete_RejectsUnknownFields(t *testing.T) {
	// DisallowUnknownFields means an attacker can't smuggle extra fields
	// into the request body — useful both for forward-compat and to catch
	// typo'd field names that would silently bypass validation.
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t,
		map[string]any{"login_event_id": "le1", "id_token": "tok", "extra": "smuggled"}, nil)

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFedCMGoogleComplete_RejectsMissingLoginEventID(t *testing.T) {
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t,
		map[string]any{"id_token": "tok"}, nil)

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFedCMGoogleComplete_RejectsMissingIDToken(t *testing.T) {
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t,
		map[string]any{"login_event_id": "le1"}, nil)

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFedCMGoogleComplete_RejectsOversizedBody(t *testing.T) {
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()

	// Build a body deliberately larger than fedcmGoogleCompleteMaxBody. The
	// LimitReader inside the handler should truncate, producing a JSON
	// parse error on the truncated bytes.
	big := strings.Repeat("A", fedcmGoogleCompleteMaxBody+1024)
	body := []byte(`{"login_event_id":"le1","id_token":"` + big + `"}`)

	req := httptest.NewRequest(http.MethodPost, "/s/social/google/fedcm-complete",
		bytes.NewReader(body))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"oversized body must be refused at decode time")
}

func TestFedCMGoogleComplete_ResponseHeadersOnEarlyExit(t *testing.T) {
	// Locks in the Content-Type + no-store cache header on the JSON
	// response. PostHog dashboards aside, no-store matters because we
	// don't want a stuck CDN caching a "rate-limited" or "invalid_request"
	// response for the next user on the same NAT.
	h := fedcmEndpointHarness()
	rec := httptest.NewRecorder()
	req := newGoogleFedCMRequest(t,
		map[string]any{"login_event_id": "", "id_token": ""}, nil)

	require.NoError(t, h.FedCMGoogleCompleteEndpoint(rec, req))
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}
