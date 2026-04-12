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
	"github.com/pitabwire/frame/frametests/definition"
	"github.com/pitabwire/frame/frametests/deps/testoryketo"
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

const oplNamespaces = `import { Namespace, Context } from "@ory/keto-namespace-types"

class profile_user implements Namespace {}

class tenancy_access implements Namespace {
  related: {
    owner: (profile_user | SubjectSet<tenancy_access, "owner">)[]
    admin: (profile_user | SubjectSet<tenancy_access, "admin">)[]
    member: (profile_user | SubjectSet<tenancy_access, "member">)[]
    service: (profile_user | SubjectSet<tenancy_access, "service">)[]
  }
}

// Core service namespaces that receive direct role tuples alongside
// service_tenancy when a user is assigned a partition role.

class service_profile implements Namespace {
  related: {
    owner: profile_user[]
    admin: profile_user[]
    member: profile_user[]
    service: (profile_user | tenancy_access)[]
  }
}

class service_device implements Namespace {
  related: {
    owner: profile_user[]
    admin: profile_user[]
    member: profile_user[]
    service: (profile_user | tenancy_access)[]
  }
}

class service_setting implements Namespace {
  related: {
    owner: profile_user[]
    admin: profile_user[]
    member: profile_user[]
    service: (profile_user | tenancy_access)[]
  }
}

class service_audit implements Namespace {
  related: {
    owner: profile_user[]
    admin: profile_user[]
    member: profile_user[]
    service: (profile_user | tenancy_access)[]
  }
}

class service_tenancy implements Namespace {
  related: {
    owner: profile_user[]
    admin: profile_user[]
    member: profile_user[]
    service: (profile_user | tenancy_access)[]

    // Direct permission grants (prefixed with granted_ to avoid
    // name conflict with permits — Keto skips permit evaluation
    // when a relation with the same name exists)
    granted_tenant_manage: (profile_user | service_tenancy)[]
    granted_tenant_view: (profile_user | service_tenancy)[]
    granted_partition_manage: (profile_user | service_tenancy)[]
    granted_partition_view: (profile_user | service_tenancy)[]
    granted_access_manage: (profile_user | service_tenancy)[]
    granted_access_view: (profile_user | service_tenancy)[]
    granted_roles_manage: (profile_user | service_tenancy)[]
    granted_pages_manage: (profile_user | service_tenancy)[]
    granted_pages_view: (profile_user | service_tenancy)[]
    granted_permission_grant: (profile_user | service_tenancy)[]
    granted_service_account_view: (profile_user | service_tenancy)[]
    granted_service_account_manage: (profile_user | service_tenancy)[]
    granted_client_view: (profile_user | service_tenancy)[]
    granted_client_manage: (profile_user | service_tenancy)[]
  }

  permits = {
    tenant_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.granted_tenant_manage.includes(ctx.subject),

    tenant_view: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.tenant_manage(ctx) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.member.includes(ctx.subject) ||
      this.related.granted_tenant_view.includes(ctx.subject),

    partition_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_partition_manage.includes(ctx.subject),

    partition_view: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.partition_manage(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.granted_partition_view.includes(ctx.subject),

    access_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_access_manage.includes(ctx.subject),

    access_view: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.access_manage(ctx) ||
      this.related.granted_access_view.includes(ctx.subject),

    roles_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_roles_manage.includes(ctx.subject),

    pages_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_pages_manage.includes(ctx.subject),

    pages_view: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.pages_manage(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.granted_pages_view.includes(ctx.subject),

    permission_grant: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_permission_grant.includes(ctx.subject),

    service_account_view: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_service_account_view.includes(ctx.subject),

    service_account_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.granted_service_account_manage.includes(ctx.subject),

    client_view: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.granted_client_view.includes(ctx.subject),

    client_manage: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.granted_client_manage.includes(ctx.subject),
  }
}
`

// NewWithOpts creates a new Keto test resource with OPL namespace support.
func NewWithOpts(
	containerOpts ...definition.ContainerOption,
) definition.TestResource {
	return testoryketo.NewWithNamespaces(
		ketoConfiguration,
		[]testoryketo.NamespaceFile{
			{
				ContainerPath: "/home/ory/namespaces/tenancy.ts",
				Content:       oplNamespaces,
			},
		},
		containerOpts...,
	)
}
