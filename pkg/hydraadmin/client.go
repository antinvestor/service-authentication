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

// Package hydraadmin builds HTTP clients for the Ory Hydra admin API.
//
// Cluster-era deployments reach Hydra admin over plain http:// inside the
// mesh (no auth). Cloud Run exposes admin as IAM-authenticated HTTPS
// (e.g. https://oauth2-w.stawi.org); callers must attach a Google ID token
// minted for that origin so roles/run.invoker accepts the request.
//
// Service OAuth2 client-credentials / private_key_jwt are intentionally
// never attached: bootstrap would otherwise circular-depend on Hydra
// itself (tenancy registering its own client; authentication fetching JWKS).
package hydraadmin

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/pitabwire/frame/v2/client"
	"github.com/pitabwire/util"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// NewManager returns a client.Manager for Hydra admin.
// https admin URIs get a Google ID token transport; http:// stays plain.
func NewManager(ctx context.Context, adminURI string, opts ...client.HTTPOption) client.Manager {
	// Background context so Frame does not auto-attach service OAuth2 tokens
	// from the runtime config (bootstrap circularity).
	mgr := client.NewManager(context.Background(), opts...)
	if cl := withGoogleIDToken(ctx, mgr.Client(ctx), adminURI); cl != nil {
		mgr.SetClient(ctx, cl)
	}
	return mgr
}

// NewHTTPClient returns an *http.Client for Hydra admin (same auth rules as NewManager).
func NewHTTPClient(ctx context.Context, adminURI string, opts ...client.HTTPOption) *http.Client {
	base := client.NewHTTPClient(context.Background(), opts...)
	if cl := withGoogleIDToken(ctx, base, adminURI); cl != nil {
		return cl
	}
	return base
}

// withGoogleIDToken wraps base with oauth2.Transport when adminURI is https.
// Returns nil when no wrap is needed or the token source cannot be created
// (caller keeps the unauthenticated client; Cloud Run will 403 until fixed).
func withGoogleIDToken(ctx context.Context, base *http.Client, adminURI string) *http.Client {
	if base == nil {
		return nil
	}
	audience := AudienceFromHTTPSURI(adminURI)
	if audience == "" {
		return nil
	}
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		util.Log(ctx).WithError(err).WithField("audience", audience).
			Warn("hydra admin: Google ID token source unavailable; Cloud Run invoker calls may 403")
		return nil
	}
	return &http.Client{
		Transport: &oauth2.Transport{
			Base:   base.Transport,
			Source: oauth2.ReuseTokenSource(nil, ts),
		},
		Timeout:       base.Timeout,
		Jar:           base.Jar,
		CheckRedirect: base.CheckRedirect,
	}
}

// AudienceFromHTTPSURI returns https://host for Cloud Run ID-token audience,
// or empty for non-https / unparseable URIs (cluster-internal http).
func AudienceFromHTTPSURI(rawURI string) string {
	u, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil || u.Host == "" || !strings.EqualFold(u.Scheme, "https") {
		return ""
	}
	return "https://" + u.Host
}
