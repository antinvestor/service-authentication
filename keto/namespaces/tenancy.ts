import { Namespace, Context } from "@ory/keto-namespace-types"

class profile implements Namespace {}

class tenancy_tenant implements Namespace {
  related: {
    owner: profile[]
    admin: profile[]
    member: profile[]

    // Direct permission grants
    manage_tenant: profile[]
    view_tenant: profile[]
    manage_partition: profile[]
    view_partition: profile[]
    manage_access: profile[]
    view_access: profile[]
    manage_roles: profile[]
    manage_pages: profile[]
    view_pages: profile[]
    grant_permission: profile[]
  }

  permits = {
    manage_tenant: (ctx: Context): boolean =>
      this.related.owner.includes(ctx.subject) ||
      this.related.manage_tenant.includes(ctx.subject),

    view_tenant: (ctx: Context): boolean =>
      this.permits.manage_tenant(ctx) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_tenant.includes(ctx.subject),

    manage_partition: (ctx: Context): boolean =>
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_partition.includes(ctx.subject),

    view_partition: (ctx: Context): boolean =>
      this.permits.manage_partition(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_partition.includes(ctx.subject),

    manage_access: (ctx: Context): boolean =>
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_access.includes(ctx.subject),

    view_access: (ctx: Context): boolean =>
      this.permits.manage_access(ctx) ||
      this.related.view_access.includes(ctx.subject),

    manage_roles: (ctx: Context): boolean =>
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_roles.includes(ctx.subject),

    manage_pages: (ctx: Context): boolean =>
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.manage_pages.includes(ctx.subject),

    view_pages: (ctx: Context): boolean =>
      this.permits.manage_pages(ctx) ||
      this.related.member.includes(ctx.subject) ||
      this.related.view_pages.includes(ctx.subject),

    grant_permission: (ctx: Context): boolean =>
      this.related.owner.includes(ctx.subject) ||
      this.related.admin.includes(ctx.subject) ||
      this.related.grant_permission.includes(ctx.subject),
  }
}
