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

// Package opl generates Ory Keto OPL (Open Policy Language) TypeScript from
// the registered ServiceNamespace records and pushes it to a Kubernetes
// ConfigMap so Keto can reload its namespace configuration.
//
// The generated OPL is sectioned by domain (platform, fintech, communication,
// storage) with clear markers. Today everything goes into one combined file
// for a single Keto instance. To split later: generate per-domain files
// and point each Keto instance at its own ConfigMap.
package opl

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
)

// roleOrder defines the canonical order roles appear in OPL output.
var roleOrder = []string{"owner", "admin", "operator", "viewer", "member", "service"}

// reservedNamespaces are emitted by writeSharedClasses and must not be
// duplicated from service registrations.
var reservedNamespaces = map[string]bool{
	"profile_user":   true,
	"tenancy_access": true,
}

// GenerateCombined produces a single OPL TypeScript string from all registered
// namespaces. Namespaces are grouped by Domain with section markers so the
// output is easy to split into per-domain files later.
//
// Reserved namespaces (profile_user, tenancy_access) and duplicates are
// automatically filtered out.
func GenerateCombined(namespaces []*models.ServiceNamespace) string {
	namespaces = dedup(namespaces)
	grouped := groupByDomain(namespaces)

	var b strings.Builder
	writeHeader(&b)
	writeSharedClasses(&b)

	// Deterministic domain ordering.
	domains := domainOrder(grouped)
	for _, domain := range domains {
		nsList := grouped[domain]
		sort.Slice(nsList, func(i, j int) bool {
			return nsList[i].Namespace < nsList[j].Namespace
		})

		b.WriteString("\n// ═══════════════════════════════════════════════════════════════════════\n")
		fmt.Fprintf(&b, "// Domain: %s\n", domain)
		b.WriteString("// ═══════════════════════════════════════════════════════════════════════\n")

		for _, ns := range nsList {
			b.WriteString("\n")
			writeNamespaceClass(&b, ns)
		}
	}

	return b.String()
}

// GenerateForDomain produces OPL for a single domain only, including the
// shared header and base classes. Use this when splitting into per-domain
// files for separate Keto instances.
func GenerateForDomain(namespaces []*models.ServiceNamespace, domain string) string {
	namespaces = dedup(namespaces)
	var filtered []*models.ServiceNamespace
	for _, ns := range namespaces {
		if effectiveDomain(ns) == domain {
			filtered = append(filtered, ns)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Namespace < filtered[j].Namespace
	})

	var b strings.Builder
	writeHeader(&b)
	writeSharedClasses(&b)

	for _, ns := range filtered {
		b.WriteString("\n")
		writeNamespaceClass(&b, ns)
	}
	return b.String()
}

func writeHeader(b *strings.Builder) {
	b.WriteString("import { Namespace, Context } from \"@ory/keto-namespace-types\"\n")
}

func writeSharedClasses(b *strings.Builder) {
	b.WriteString("\n// Shared base namespaces used across all services.\n")
	b.WriteString("class profile_user implements Namespace {}\n\n")
	b.WriteString("class tenancy_access implements Namespace {\n")
	b.WriteString("  related: {\n")
	b.WriteString("    owner: (profile_user | SubjectSet<tenancy_access, \"owner\">)[]\n")
	b.WriteString("    admin: (profile_user | SubjectSet<tenancy_access, \"admin\">)[]\n")
	b.WriteString("    member: (profile_user | SubjectSet<tenancy_access, \"member\">)[]\n")
	b.WriteString("    service: (profile_user | SubjectSet<tenancy_access, \"service\">)[]\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
}

func writeNamespaceClass(b *strings.Builder, ns *models.ServiceNamespace) {
	namespace := ns.Namespace
	permissions := extractPermissions(ns.Permissions)
	rolePerms := invertRoleBindings(extractRoleBindings(ns.RoleBindings))

	fmt.Fprintf(b, "class %s implements Namespace {\n", namespace)

	// Related section: roles + granted_<perm> relations.
	b.WriteString("  related: {\n")
	for _, role := range roleOrder {
		if role == "service" {
			fmt.Fprintf(b, "    %s: (profile_user | tenancy_access)[]\n", role)
		} else {
			fmt.Fprintf(b, "    %s: profile_user[]\n", role)
		}
	}
	if len(permissions) > 0 {
		b.WriteString("\n")
		for _, perm := range permissions {
			fmt.Fprintf(b, "    granted_%s: (profile_user | %s)[]\n", perm, namespace)
		}
	}
	b.WriteString("  }\n")

	// Permits section.
	if len(permissions) > 0 {
		b.WriteString("\n  permits = {\n")
		for i, perm := range permissions {
			if i > 0 {
				b.WriteString("\n")
			}
			writePermit(b, perm, rolePerms)
		}
		b.WriteString("  }\n")
	}

	b.WriteString("}\n")
}

func writePermit(b *strings.Builder, perm string, rolePerms map[string][]string) {
	fmt.Fprintf(b, "    %s: (ctx: Context): boolean =>\n", perm)

	roles := rolePerms[perm]
	sort.Strings(roles)

	var conditions []string
	for _, role := range roles {
		conditions = append(conditions, fmt.Sprintf("      this.related.%s.includes(ctx.subject)", role))
	}
	conditions = append(conditions, fmt.Sprintf("      this.related.granted_%s.includes(ctx.subject)", perm))

	b.WriteString(strings.Join(conditions, " ||\n"))
	b.WriteString(",\n")
}

// --- Helpers ---

// dedup removes reserved namespace names (already emitted as shared classes)
// and duplicate namespace entries, keeping the first occurrence.
func dedup(namespaces []*models.ServiceNamespace) []*models.ServiceNamespace {
	seen := make(map[string]bool, len(namespaces))
	for ns := range reservedNamespaces {
		seen[ns] = true
	}
	result := make([]*models.ServiceNamespace, 0, len(namespaces))
	for _, ns := range namespaces {
		if seen[ns.Namespace] {
			continue
		}
		seen[ns.Namespace] = true
		result = append(result, ns)
	}
	return result
}

func effectiveDomain(ns *models.ServiceNamespace) string {
	if ns.Domain != "" {
		return ns.Domain
	}
	return models.DomainDefault
}

func groupByDomain(namespaces []*models.ServiceNamespace) map[string][]*models.ServiceNamespace {
	grouped := make(map[string][]*models.ServiceNamespace)
	for _, ns := range namespaces {
		d := effectiveDomain(ns)
		grouped[d] = append(grouped[d], ns)
	}
	return grouped
}

// domainOrder returns domains sorted alphabetically for deterministic output.
// The default domain ("platform") sorts naturally among others.
func domainOrder(grouped map[string][]*models.ServiceNamespace) []string {
	domains := make([]string, 0, len(grouped))
	for d := range grouped {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

func extractPermissions(m map[string]any) []string {
	raw, ok := m["values"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func extractRoleBindings(m map[string]any) map[string][]string {
	result := make(map[string][]string, len(m))
	for role, raw := range m {
		switch typed := raw.(type) {
		case []any:
			perms := make([]string, 0, len(typed))
			for _, v := range typed {
				if s, ok := v.(string); ok {
					perms = append(perms, s)
				}
			}
			result[role] = perms
		case []string:
			result[role] = typed
		}
	}
	return result
}

// invertRoleBindings converts role→[]permissions into permission→[]roles.
func invertRoleBindings(bindings map[string][]string) map[string][]string {
	result := make(map[string][]string)
	for role, perms := range bindings {
		for _, perm := range perms {
			result[perm] = append(result[perm], role)
		}
	}
	return result
}
