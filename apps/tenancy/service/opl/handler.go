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
	"fmt"
	"net/http"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const (
	defaultDomain             = models.DomainDefault
	defaultConfigMapName      = "keto-namespace-combined"
	defaultConfigMapNamespace = "auth"
	defaultConfigMapKey       = "namespaces.ts"
)

// NewHandler returns an HTTP handler that serves Keto OPL generated from
// all registered service namespaces.
//
// Query parameters:
//   - domain:    domain filter (default: "platform"). Use "all" for combined.
//   - format:    "configmap" (default) returns a Kubernetes ConfigMap YAML
//     ready for kubectl apply or kustomize. "raw" returns plain
//     TypeScript.
//   - name:      ConfigMap name (default: "keto-namespace-combined")
//   - namespace: ConfigMap namespace (default: "auth")
//   - key:       ConfigMap data key (default: "namespaces.ts")
//
// Examples:
//
//	GET /_internal/opl                              → ConfigMap YAML for platform domain
//	GET /_internal/opl?domain=all                   → ConfigMap YAML for all domains combined
//	GET /_internal/opl?domain=fintech               → ConfigMap YAML for fintech domain only
//	GET /_internal/opl?format=raw                   → plain OPL TypeScript
//	GET /_internal/opl?name=keto-ns-fintech&namespace=fintech
//
// This endpoint is unauthenticated and cluster-internal only.
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

		domain := queryOrDefault(r, "domain", defaultDomain)
		format := queryOrDefault(r, "format", "configmap")

		var oplContent string
		if domain == "all" {
			oplContent = GenerateCombined(namespaces)
		} else {
			oplContent = GenerateForDomain(namespaces, domain)
		}

		if format == "raw" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(oplContent))
			return
		}

		// Default: return a Kubernetes ConfigMap YAML.
		cmName := queryOrDefault(r, "name", defaultConfigMapName)
		cmNamespace := queryOrDefault(r, "namespace", defaultConfigMapNamespace)
		cmKey := queryOrDefault(r, "key", defaultConfigMapKey)

		configMap := renderConfigMap(cmName, cmNamespace, cmKey, oplContent)

		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(configMap))
	})
}

// renderConfigMap produces a Kubernetes ConfigMap YAML manifest with the OPL
// content embedded as a data key. The output is ready for kubectl apply or
// kustomize resource reference.
func renderConfigMap(name, namespace, key, oplContent string) string {
	var b strings.Builder

	b.WriteString("apiVersion: v1\n")
	b.WriteString("kind: ConfigMap\n")
	b.WriteString("metadata:\n")
	fmt.Fprintf(&b, "  name: %s\n", name)
	fmt.Fprintf(&b, "  namespace: %s\n", namespace)
	b.WriteString("data:\n")
	fmt.Fprintf(&b, "  %s: |\n", key)

	// Indent every line of the OPL content by 4 spaces for YAML block scalar.
	for _, line := range strings.Split(oplContent, "\n") {
		if line == "" {
			b.WriteString("\n")
		} else {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}

	return b.String()
}

func queryOrDefault(r *http.Request, key, fallback string) string {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	return v
}
