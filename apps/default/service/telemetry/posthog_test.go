// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package telemetry_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/antinvestor/service-authentication/apps/default/service/telemetry"
)

// TestNew_NoopWhenKeyEmpty asserts that the wrapper degrades to the noop
// client when POSTHOG_API_KEY is unset. That is the contract every caller
// relies on — if it ever broke, the wrapper would try to construct a real
// PostHog client with an empty key and either fail at construct time or emit
// against an invalid project.
func TestNew_NoopWhenKeyEmpty(t *testing.T) {
	ctx := context.Background()
	c := telemetry.New(ctx, "", "https://eu.posthog.com")
	require.NotNil(t, c)
	require.NotPanics(t, func() {
		c.Capture(ctx, "anon", "event_a", nil)
		c.Alias(ctx, "anon", "user-1")
		require.NoError(t, c.Close())
	})
}

// TestNew_RealClientWithKey makes sure the constructor returns a usable
// client when a key is supplied. We pick a phc_test_* style key — the SDK
// only checks the key is non-empty at New time; the actual HTTP request is
// async and we explicitly do not assert on it here to keep the test
// hermetic.
func TestNew_RealClientWithKey(t *testing.T) {
	ctx := context.Background()
	c := telemetry.New(ctx, "phc_test_local", "https://eu.posthog.com")
	require.NotNil(t, c)
	require.NotPanics(t, func() {
		c.Capture(ctx, "anon", "event_a", map[string]any{"k": "v"})
		c.Alias(ctx, "anon", "user-1")
		require.NoError(t, c.Close())
	})
}

// TestClose_IsIdempotent guarantees the wrapper can be Closed twice without
// returning an error or panicking — the deferred Close pattern is common in
// callers and a hidden second-close panic would crash request handlers.
func TestClose_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	c := telemetry.New(ctx, "phc_test_local", "https://eu.posthog.com")
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
}

// TestCapture_AfterCloseIsSilent locks in the use-after-Close contract: any
// emit after Close must be silently dropped, never panic. The risk is the
// underlying SDK panicking on a closed channel if we forwarded the call.
func TestCapture_AfterCloseIsSilent(t *testing.T) {
	ctx := context.Background()
	c := telemetry.New(ctx, "phc_test_local", "https://eu.posthog.com")
	require.NoError(t, c.Close())
	require.NotPanics(t, func() {
		c.Capture(ctx, "anon", "after_close", map[string]any{"k": "v"})
		c.Alias(ctx, "anon", "user-1")
	})
}

// TestAlias_NoopOnEmptyOrSameIDs guards the wrapper's input checks. PostHog
// would treat an alias-to-self as a corrupt event; an empty pair is even
// worse. The wrapper must silently drop these.
func TestAlias_NoopOnEmptyOrSameIDs(t *testing.T) {
	ctx := context.Background()
	c := telemetry.New(ctx, "phc_test_local", "https://eu.posthog.com")
	t.Cleanup(func() { _ = c.Close() })
	require.NotPanics(t, func() {
		c.Alias(ctx, "", "user-1")
		c.Alias(ctx, "anon", "")
		c.Alias(ctx, "same", "same")
	})
}

// TestCapture_ConcurrentSafe verifies the RWMutex on phClient holds up
// under contention. If we ever regress to writing without locking, the
// race detector will catch it here.
func TestCapture_ConcurrentSafe(t *testing.T) {
	ctx := context.Background()
	c := telemetry.New(ctx, "phc_test_local", "https://eu.posthog.com")
	t.Cleanup(func() { _ = c.Close() })

	const goroutines = 8
	const perGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				c.Capture(ctx, "user-"+string(rune('a'+idx)), "concurrent_event", map[string]any{"i": j})
			}
		}(i)
	}
	wg.Wait()
}

// TestNew_NilContextSafe documents that a nil-ish context (background here)
// is fine. PostHog construction must never panic on a benign context.
func TestNew_NilContextSafe(t *testing.T) {
	require.NotPanics(t, func() {
		c := telemetry.New(context.Background(), "phc_test_local", "")
		require.NotNil(t, c)
		_ = c.Close()
	})
}

// TestAnonymousDistinctIDExported asserts the public constant has the value
// the rest of the codebase relies on. The wrapper substitutes this when an
// empty distinct ID is passed to Capture; if the value drifts, pre-login
// events would land under a different person on the PostHog dashboard.
func TestAnonymousDistinctIDExported(t *testing.T) {
	require.Equal(t, "$anon", telemetry.AnonymousDistinctID)
}
