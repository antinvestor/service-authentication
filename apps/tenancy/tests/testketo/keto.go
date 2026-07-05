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

package testketo

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/frametests/deps/testoryketo"
)

// ImageName is the Ory Keto image used for test containers.
const ImageName = testoryketo.OryKetoImage

const ketoConfiguration = `
limit:
  max_read_depth: 10

serve:
  read:
    host: 0.0.0.0
    port: 4466
  write:
    host: 0.0.0.0
    port: 4467

log:
  level: debug
  format: text

namespaces:
  location: file:///home/ory/namespaces/tenancy.ts

`

const oplHeader = `import { Namespace, Context } from "@ory/keto-namespace-types"

class profile_user implements Namespace {}

class tenancy_access implements Namespace {
  related: {
    owner: (profile_user | SubjectSet<tenancy_access, "owner">)[]
    admin: (profile_user | SubjectSet<tenancy_access, "admin">)[]
    member: (profile_user | SubjectSet<tenancy_access, "member">)[]
    service: (profile_user | SubjectSet<tenancy_access, "service">)[]
  }
}
`

func renderOPLNamespaces() string {
	var builder strings.Builder
	builder.WriteString(oplHeader)

	catalog := testPermissionCatalog()
	namespaces := make([]string, 0, len(catalog))
	for namespace := range catalog {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	for _, namespace := range namespaces {
		permissions := catalog[namespace]
		slices.Sort(permissions)

		_, _ = fmt.Fprintf(&builder, "\nclass %s implements Namespace {\n  related: {\n", namespace)
		builder.WriteString("    owner: profile_user[]\n")
		builder.WriteString("    admin: profile_user[]\n")
		builder.WriteString("    operator: profile_user[]\n")
		builder.WriteString("    viewer: profile_user[]\n")
		builder.WriteString("    member: profile_user[]\n")
		for _, permission := range permissions {
			_, _ = fmt.Fprintf(
				&builder,
				"    granted_%s: (profile_user | %s)[]\n",
				permission,
				namespace,
			)
		}
		builder.WriteString("  }\n")

		if len(permissions) > 0 {
			builder.WriteString("\n  permits = {\n")
			for _, permission := range permissions {
				_, _ = fmt.Fprintf(
					&builder,
					"    %s: (ctx: Context): boolean =>\n"+
						"      this.related.owner.includes(ctx.subject) ||\n"+
						"      this.related.granted_%s.includes(ctx.subject),\n",
					permission,
					permission,
				)
			}
			builder.WriteString("  }\n")
		}
		builder.WriteString("}\n")
	}

	return builder.String()
}

func testPermissionCatalog() map[string][]string {
	return map[string][]string{
		"service_profile": {"profile_update", "profile_view"},
		"service_tenancy": {
			"access_manage", "access_view", "client_manage", "client_view", "page_manage", "page_view",
			"partition_manage", "partition_view", "permission_grant", "role_manage", "service_account_manage",
			"service_account_view", "tenant_manage", "tenant_view",
		},
	}
}

// NewWithOpts creates a new Keto test resource with OPL namespace support.
func NewWithOpts(
	containerOpts ...definition.ContainerOption,
) definition.TestResource {
	return testoryketo.NewWithNamespaces(
		ketoConfiguration,
		[]testoryketo.NamespaceFile{
			{
				ContainerPath: "/home/ory/namespaces/tenancy.ts",
				Content:       renderOPLNamespaces(),
			},
		},
		containerOpts...,
	)
}
