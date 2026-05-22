// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package handlers

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/antinvestor/service-authentication/apps/default/service/telemetry"
	"github.com/antinvestor/service-authentication/apps/default/utils"
)

// recordingClient is a test-double telemetry.Client that captures every
// emit so assertions can inspect them. Concurrent-safe because the wrapper
// is supposed to be concurrent-safe and we want any locking regression to
// reproduce in tests too.
type recordingClient struct {
	mu       sync.Mutex
	captures []captureCall
	aliases  []aliasCall
}

type captureCall struct {
	DistinctID string
	Event      string
	Props      map[string]any
}

type aliasCall struct {
	AnonymousID string
	UserID      string
}

func (r *recordingClient) Capture(_ context.Context, distinctID, event string, props map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.captures = append(r.captures, captureCall{distinctID, event, props})
}

func (r *recordingClient) Alias(_ context.Context, anonymousID, userID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aliases = append(r.aliases, aliasCall{anonymousID, userID})
}

func (r *recordingClient) Close() error { return nil }

// Compile-time check that recordingClient still implements the interface
// even after future refactors of telemetry.Client.
var _ telemetry.Client = (*recordingClient)(nil)

// TestAnalyticsDistinctID_FallbackChain locks in the precedence: explicit
// profileID wins; session ID is the next-best identifier; "$anon" is the
// final fallback. If this regressed, anonymous pre-login funnels would
// land under "$anon" for every user instead of clustering per browser.
func TestAnalyticsDistinctID_FallbackChain(t *testing.T) {
	tests := []struct {
		name       string
		profileID  string
		sessionID  string
		wantPrefix string
	}{
		{"profile wins", "profile-1", "sess-1", "profile-1"},
		{"session when no profile", "", "sess-2", "sess-2"},
		{"anonymous fallback", "", "", telemetry.AnonymousDistinctID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.sessionID != "" {
				ctx = utils.SessionIDToContext(ctx, tc.sessionID)
			}
			got := analyticsDistinctID(ctx, tc.profileID)
			require.Equal(t, tc.wantPrefix, got)
		})
	}
}

// TestEmitAnalyticsEvent_AttachesRequestMetadata verifies the wrapper
// auto-populates the $ip / $user_agent / $current_url properties from the
// HTTP request. Dashboards built on those property names would silently
// stop receiving them if the wrapper ever stopped attaching them.
func TestEmitAnalyticsEvent_AttachesRequestMetadata(t *testing.T) {
	rec := &recordingClient{}
	h := &AuthServer{analytics: rec}

	ctx := utils.SessionIDToContext(context.Background(), "sess-99")
	req := httptest.NewRequest("GET", "/s/login?login_challenge=abc", nil).WithContext(ctx)
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.RemoteAddr = "203.0.113.7:54321"

	h.emitAnalyticsEvent(ctx, req, "profile-7", "test_event", map[string]any{"extra": "value"})

	require.Len(t, rec.captures, 1)
	got := rec.captures[0]
	require.Equal(t, "profile-7", got.DistinctID)
	require.Equal(t, "test_event", got.Event)
	require.Equal(t, "value", got.Props["extra"])
	require.Equal(t, "test-agent/1.0", got.Props["$user_agent"])
	require.Contains(t, got.Props["$current_url"], "/s/login")
	require.NotEmpty(t, got.Props["$ip"], "IP should be auto-attached")
}

// TestEmitAnalyticsEvent_DropsNilValues guards against accidentally
// emitting `prop: nil` into PostHog — that shows up as an empty string
// in dashboards and corrupts pivots.
func TestEmitAnalyticsEvent_DropsNilValues(t *testing.T) {
	rec := &recordingClient{}
	h := &AuthServer{analytics: rec}
	ctx := context.Background()

	h.emitAnalyticsEvent(ctx, nil, "profile-1", "event_with_nil", map[string]any{
		"present": "yes",
		"absent":  nil,
	})

	require.Len(t, rec.captures, 1)
	props := rec.captures[0].Props
	require.Equal(t, "yes", props["present"])
	_, hasAbsent := props["absent"]
	require.False(t, hasAbsent, "nil values must be filtered out")
}

// TestEmitAnalyticsEvent_NilAnalyticsClientIsSafe documents that the
// wrapper is safe when AuthServer's analytics field is nil (defensive —
// in production telemetry.New always returns a non-nil noop, but
// individual tests construct AuthServer literals).
func TestEmitAnalyticsEvent_NilAnalyticsClientIsSafe(t *testing.T) {
	h := &AuthServer{}
	require.NotPanics(t, func() {
		h.emitAnalyticsEvent(context.Background(), nil, "", "any_event", nil)
	})
}

// TestEmitLoginCompleted_AliasesSessionToProfile is the load-bearing
// behaviour for the FedCM funnel: pre-login events emitted under the
// session ID must be linked to the profile ID via Alias so the PostHog
// person timeline merges. If this regressed, conversion dashboards would
// show every login as a "new visitor".
func TestEmitLoginCompleted_AliasesSessionToProfile(t *testing.T) {
	rec := &recordingClient{}
	h := &AuthServer{analytics: rec}

	ctx := utils.SessionIDToContext(context.Background(), "sess-42")
	req := httptest.NewRequest("POST", "/s/login/abc/post", nil).WithContext(ctx)

	h.emitLoginCompleted(ctx, req, "profile-42", "contact", "client-X")

	require.Len(t, rec.aliases, 1, "Alias should be emitted exactly once")
	require.Equal(t, "sess-42", rec.aliases[0].AnonymousID)
	require.Equal(t, "profile-42", rec.aliases[0].UserID)

	require.Len(t, rec.captures, 1)
	require.Equal(t, evtLoginCompleted, rec.captures[0].Event)
	require.Equal(t, "profile-42", rec.captures[0].DistinctID)
	require.Equal(t, "contact", rec.captures[0].Props["method"])
	require.Equal(t, "client-X", rec.captures[0].Props["client_id"])
}

// TestEmitLoginCompleted_NoAliasWhenIDsMatch makes sure we don't
// emit a self-alias when session == profile (e.g. session ID happened to
// be reassigned to the profile ID upstream).
func TestEmitLoginCompleted_NoAliasWhenIDsMatch(t *testing.T) {
	rec := &recordingClient{}
	h := &AuthServer{analytics: rec}

	ctx := utils.SessionIDToContext(context.Background(), "same-id")
	req := httptest.NewRequest("POST", "/s/login/abc/post", nil).WithContext(ctx)

	h.emitLoginCompleted(ctx, req, "same-id", "contact", "client-X")

	require.Empty(t, rec.aliases, "no Alias for matching IDs")
	require.Len(t, rec.captures, 1)
}

// TestEmitLoginCompleted_NoAliasWhenNoSession covers the path where the
// session cookie hadn't been issued yet at the time of login (rare but
// possible during programmatic-test flows): the helper should still emit
// the login_completed event but skip Alias.
func TestEmitLoginCompleted_NoAliasWhenNoSession(t *testing.T) {
	rec := &recordingClient{}
	h := &AuthServer{analytics: rec}

	ctx := context.Background()
	req := httptest.NewRequest("POST", "/s/login/abc/post", nil).WithContext(ctx)

	h.emitLoginCompleted(ctx, req, "profile-7", "contact", "client-X")

	require.Empty(t, rec.aliases)
	require.Len(t, rec.captures, 1)
}
