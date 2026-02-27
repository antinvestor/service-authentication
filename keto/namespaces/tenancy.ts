import { Namespace, Context } from "@ory/keto-namespace-types"

class default_profile implements Namespace {}

class tenancy_access implements Namespace {
  related: {
    member: (default_profile | tenancy_access)[]
    service: default_profile[]
  }
}

class service_tenancy implements Namespace {
  related: {
    owner: default_profile[]
    admin: default_profile[]
    member: default_profile[]
    service: (default_profile | tenancy_access)[]

    // Direct permission grants (accept service_tenancy subject sets for service role bridging)
    manage_tenant: (default_profile | service_tenancy)[]
    view_tenant: (default_profile | service_tenancy)[]
    manage_partition: (default_profile | service_tenancy)[]
    view_partition: (default_profile | service_tenancy)[]
    manage_access: (default_profile | service_tenancy)[]
    view_access: (default_profile | service_tenancy)[]
    manage_roles: (default_profile | service_tenancy)[]
    manage_pages: (default_profile | service_tenancy)[]
    view_pages: (default_profile | service_tenancy)[]
    grant_permission: (default_profile | service_tenancy)[]
  }

  permits = {
    manage_tenant: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.manage_tenant.includes(ctx.subject),

    view_tenant: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_tenant(ctx) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_tenant.includes(ctx.subject),

    manage_partition: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_partition.includes(ctx.subject),

    view_partition: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_partition(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_partition.includes(ctx.subject),

    manage_access: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_access.includes(ctx.subject),

    view_access: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_access(ctx) ||
      this.related.view_access.includes(ctx.subject),

    manage_roles: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_roles.includes(ctx.subject),

    manage_pages: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_pages.includes(ctx.subject),

    view_pages: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.permits.manage_pages(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_pages.includes(ctx.subject),

    grant_permission: (ctx: Context): boolean =>
      this.related.service.includes(ctx.subject) ||
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.grant_permission.includes(ctx.subject),
  }
}
