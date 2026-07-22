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

package providers

import (
	"context"
	"net/http"
	"time"

	"github.com/pitabwire/frame/v2/client"
	"golang.org/x/oauth2"
)

// externalIdPHTTPTimeout bounds Google/Apple/Meta/Microsoft token exchanges.
// Set once on the shared HTTP client; CompleteLogin injects it via oauth2 context.
const externalIdPHTTPTimeout = 5 * time.Second

// newExternalIDPHTTPClient builds a Frame HTTP client with no service OAuth
// (external IdPs use their own credentials) and a fixed request timeout.
func newExternalIDPHTTPClient(ctx context.Context) *http.Client {
	return client.NewHTTPClient(ctx,
		client.WithHTTPTimeout(externalIdPHTTPTimeout),
		client.WithHTTPNoAuth(),
	)
}

// withOAuthHTTPClient attaches the IdP HTTP client for oauth2.Exchange / HTTP
// helpers so calls do not fall back to http.DefaultClient (unbounded).
func withOAuthHTTPClient(ctx context.Context, httpCli *http.Client) context.Context {
	if httpCli == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, httpCli)
}
