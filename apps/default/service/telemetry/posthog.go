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

// Package telemetry wraps PostHog product analytics so the rest of the auth
// service can emit events without depending on the SDK directly. The wrapper:
//
//   - Falls back to a noop client when the API key is empty, so analytics can
//     be disabled per-environment by clearing POSTHOG_API_KEY without code
//     changes.
//   - Hides the difference between authenticated users (DistinctId = profile
//     ID) and anonymous pre-login visitors (DistinctId = synthetic session ID
//     or "$anon").
//   - Never returns an error to the caller. The PostHog SDK already enqueues
//     asynchronously; surfacing transient transport errors would just train
//     handlers to ignore them. We log inside the wrapper if needed.
package telemetry

import (
	"context"
	"sync"

	"github.com/pitabwire/util"
	"github.com/posthog/posthog-go"
)

// AnonymousDistinctID is the DistinctId used when an event is emitted before
// we know who the user is (e.g. on the login page load). PostHog merges
// events under this ID into the eventual profile_id with an Alias call when
// we later identify the user.
const AnonymousDistinctID = "$anon"

// Client is the surface the rest of the codebase uses. The wrapper concept
// matters because we want a usable zero-value (noop) at every callsite —
// callers shouldn't need to check `if client != nil` before every emit.
type Client interface {
	// Capture records an event. distinctID identifies the user; pass
	// AnonymousDistinctID before login completes. props may be nil. Safe to
	// call from any goroutine.
	Capture(ctx context.Context, distinctID, event string, props map[string]any)

	// Alias links a previously-anonymous distinct ID to a stable user ID so
	// pre-login events show up on the same person timeline as post-login
	// ones. Safe to call from any goroutine.
	Alias(ctx context.Context, anonymousID, userID string)

	// Close flushes pending events and shuts down the SDK. Safe to call
	// multiple times.
	Close() error
}

// New constructs a Client from the given configuration. When apiKey is empty
// it returns a noop client; otherwise it constructs a real PostHog client
// using the supplied host. Any SDK construction error is logged and reduced
// to the noop client — the auth service never refuses to start because
// analytics are misconfigured.
func New(ctx context.Context, apiKey, host string) Client {
	if apiKey == "" {
		return noop{}
	}
	cfg := posthog.Config{}
	if host != "" {
		cfg.Endpoint = host
	}
	c, err := posthog.NewWithConfig(apiKey, cfg)
	if err != nil {
		util.Log(ctx).WithError(err).Warn("posthog init failed; analytics disabled")
		return noop{}
	}
	return &phClient{inner: c}
}

// phClient wraps the real PostHog SDK. The mutex guards Close so the wrapper
// is safe to use concurrently with shutdown — Capture calls that race with
// Close are silently dropped rather than panicking on a closed channel
// inside the SDK.
type phClient struct {
	mu     sync.RWMutex
	inner  posthog.Client
	closed bool
}

func (c *phClient) Capture(_ context.Context, distinctID, event string, props map[string]any) {
	if c == nil {
		return
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.inner == nil {
		return
	}
	if distinctID == "" {
		distinctID = AnonymousDistinctID
	}

	properties := posthog.NewProperties()
	for k, v := range props {
		properties.Set(k, v)
	}

	_ = c.inner.Enqueue(posthog.Capture{
		DistinctId: distinctID,
		Event:      event,
		Properties: properties,
	})
}

func (c *phClient) Alias(_ context.Context, anonymousID, userID string) {
	if c == nil {
		return
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.inner == nil {
		return
	}
	if anonymousID == "" || userID == "" || anonymousID == userID {
		return
	}
	_ = c.inner.Enqueue(posthog.Alias{
		Alias:      anonymousID,
		DistinctId: userID,
	})
}

func (c *phClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.inner == nil {
		return nil
	}
	return c.inner.Close()
}

// noop satisfies the Client interface without emitting anything. Used when
// PostHogAPIKey is empty (analytics intentionally disabled) or when SDK
// construction fails.
type noop struct{}

func (noop) Capture(context.Context, string, string, map[string]any) {}
func (noop) Alias(context.Context, string, string)                   {}
func (noop) Close() error                                            { return nil }
