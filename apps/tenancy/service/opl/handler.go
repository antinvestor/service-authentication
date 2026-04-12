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

package opl

import (
	"net/http"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

// NewHandler returns an HTTP handler that serves the combined Keto OPL
// generated from all registered service namespaces. The response is
// TypeScript content suitable for Keto's namespace configuration.
//
// Query parameters:
//   - domain: if set, returns OPL for that domain only (for per-domain Keto instances)
//
// This endpoint is unauthenticated and intended for cluster-internal use
// (init containers, sidecars, or CronJobs that populate Keto's config).
func NewHandler(repo repository.ServiceNamespaceRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := security.SkipTenancyChecksOnClaims(r.Context())

		namespaces, err := repo.ListAll(ctx)
		if err != nil {
			util.Log(ctx).WithError(err).Error("failed to load service namespaces for OPL")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		domain := r.URL.Query().Get("domain")

		var content string
		if domain != "" {
			content = GenerateForDomain(namespaces, domain)
		} else {
			content = GenerateCombined(namespaces)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})
}
