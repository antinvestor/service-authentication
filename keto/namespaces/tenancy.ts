import { Namespace, Context } from "@ory/keto-namespace-types"

class profile_user implements Namespace {}

class tenancy_access implements Namespace {
  related: {
    member: (profile_user | tenancy_access)[]
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
  }
}
