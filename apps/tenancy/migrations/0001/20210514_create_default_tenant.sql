--- Copyright 2023-2026 Ant Investor Ltd
---
--- Licensed under the Apache License, Version 2.0 (the "License");
--- you may not use this file except in compliance with the License.
--- You may obtain a copy of the License at
---
---      http://www.apache.org/licenses/LICENSE-2.0
---
--- Unless required by applicable law or agreed to in writing, software
--- distributed under the License is distributed on an "AS IS" BASIS,
--- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--- See the License for the specific language governing permissions and
--- limitations under the License.

-- ==========================================================================
-- ORIGIN ROOT TENANT: Thesa
-- ==========================================================================
--
-- This is the single root tenant from which all environment-specific tenants
-- (production, staging) derive. Service accounts and super users are created
-- at this level, giving them authority across all environments.
--
-- Entity relationships (service accounts in separate migration):
--
--   Tenant (Thesa)
--     └─ Partition (Thesa)                         ← the origin partition
--          ├─ Client (d6qbqdkpf2t52mcunf30)          ← Thesa production (authorization_code)
--          ├─ Client (d6qbqdkpf2t52mcunf3g)          ← Thesa dev (authorization_code)
--          ├─ PartitionRole (owner, admin, member)   ← standard role set
--          ├─ Access (d75qclkpf2t1uum8ij30)          ← Platform Admin (bwire517@gmail.com)
--          ├─ AccessRole (d75qclkpf2t1uum8ij23)     ← Admin → owner role
--          └─ AccessRole (d75qclkpf2t1uum8ij24)     ← Admin → member role (base access)
--
-- Service account clients + service_accounts are seeded in:
--   20260306_seed_service_accounts_production.sql
--
-- The Platform Admin profile (d75qclkpf2t1uum8ij3g) is created by the
-- profile service migration (20260331_bootstrap_profiles.sql). Its contact
-- (bwire517@gmail.com) is encrypted and linked at app startup.
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Thesa', 'Origin root tenant from which all environments derive', 'production');

-- Partition
INSERT INTO partitions (id, tenant_id, partition_id, name, description, allow_auto_access, properties)
VALUES ('c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Thesa', 'Origin root partition — parent of all environment partitions', 'false', '{
    "default_role": "user",
    "support_contacts": {
      "msisdn": "+256757546244",
      "email": "info@antinvestor.com"
    }
  }');

-- Public client: Thesa production — user login via authorization_code + PKCE
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7s0',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: Thesa
    'c2f4j7au6s7f91uqnokg',                        -- partition: Thesa
    'Thesa',
    'd6qbqdkpf2t52mcunf30',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy": [],"service_device": [],"service_profile": [],"service_notification": [],"service_payment": [],"service_ledger": [],"service_setting": [],"service_thesa": [],"service_file": []}',
    '{"uris": ["https://thesa.pages.dev/auth/callback","https://thesa.stawi.org/auth/callback","org.stawi.thesa://auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["https://thesa.pages.dev/","https://thesa.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- Public client: Thesa Dev — user login via authorization_code + PKCE (development)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7sg',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: Thesa
    'c2f4j7au6s7f91uqnokg',                        -- partition: Thesa
    'Thesa Dev',
    'd6qbqdkpf2t52mcunf3g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_tenancy": [],"service_device": [],"service_profile": [],"service_notification": [],"service_payment": [],"service_ledger": [],"service_setting": [],"service_thesa": [],"service_file": []}',
    '{"uris": ["http://localhost:5173/auth/callback","https://thesa-dev.stawi.org/auth/callback","org.stawi.thesa-dev://auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["http://localhost:5173/","https://thesa-dev.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;

-- ==========================================================================
-- PARTITION ROLES: standard roles for the Thesa root partition
-- ==========================================================================
--
-- Every partition needs roles that can be assigned to users via access_roles.
-- When an access_role is created, the tenancy service emits a Keto tuple
-- write event that grants the user the role in the service_tenancy namespace
-- and all service namespaces declared in the partition's client audiences.
--
-- Roles:
--   owner  — Full control across all services. Intended for platform admins.
--   admin  — Manage partitions, access, roles, pages. No tenant-level ops.
--   member — Read-only default role assigned on access creation.
--
-- is_default=true on member means it is auto-assigned when a new access
-- record is created (see accessBusiness.CreateAccess).
-- ==========================================================================
INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties)
VALUES
    ('d75qclkpf2t1uum8ij20', NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
     'owner', false, '{"description": "Full control across all services"}'),
    ('d75qclkpf2t1uum8ij21', NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('d75qclkpf2t1uum8ij22', NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- ==========================================================================
-- PLATFORM ADMIN ACCESS: bwire517@gmail.com → Thesa root partition
-- ==========================================================================
--
-- The root Thesa partition has allow_auto_access = false, which prevents
-- automatic access creation during login. Without an explicit access record,
-- the admin user's first login falls through to a child partition that has
-- auto-access enabled (e.g. Stawi), landing them in the wrong context.
--
-- This seeds an explicit access record so the platform admin is bound to the
-- root partition on first login. The profile_id references the "Platform Admin"
-- profile created by the profile service migration:
--
--   Profile:   d75qclkpf2t1uum8ij3g  (person type, "Platform Admin")
--   Contact:   bwire517@gmail.com     (seeded at app startup by SeedBootstrapContacts)
--   Partition: c2f4j7au6s7f91uqnokg  (Thesa — origin root)
--   Tenant:    c2f4j7au6s7f91uqnojg  (Thesa)
--
-- State 1 = ACTIVE (matches commonv1.STATE_ACTIVE).
-- ==========================================================================
INSERT INTO accesses (
    id, created_at, modified_at, version,
    tenant_id, partition_id, access_id,
    profile_id, state
) VALUES (
    'd75qclkpf2t1uum8ij30',                       -- static xid for the admin access record
    NOW(), NOW(), 1,
    'c2f4j7au6s7f91uqnojg',                       -- tenant: Thesa
    'c2f4j7au6s7f91uqnokg',                       -- partition: Thesa (origin root)
    '',                                            -- no parent access
    'd75qclkpf2t1uum8ij3g',                       -- profile: Platform Admin (bwire517@gmail.com)
    1                                              -- state: ACTIVE
) ON CONFLICT (id) DO NOTHING;

-- ==========================================================================
-- PLATFORM ADMIN ROLES: assign owner + member roles to the platform admin
-- ==========================================================================
--
-- Links the admin's access record to partition roles, granting full
-- permissions across all services. The tenancy service writes Keto
-- tuples for these role assignments during partition sync or when
-- access_roles are created via API.
--
-- Both owner AND member are required because:
-- - owner: grants administrative permissions across all services
-- - member: grants base data-access (tenancy_access#member) which services
--   check before evaluating any functional permissions
--
-- The tenancy_access namespace has NO OPL permits — only direct relations —
-- so owner does NOT imply member. Without the member tuple, even an owner
-- gets "permission denied: cannot member on tenancy_access".
-- ==========================================================================
INSERT INTO access_roles (id, created_at, modified_at, version, tenant_id, partition_id, access_id, partition_role_id)
VALUES
    ('d75qclkpf2t1uum8ij23',                       -- static xid for the admin owner role
     NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg',                       -- tenant: Thesa
     'c2f4j7au6s7f91uqnokg',                       -- partition: Thesa (origin root)
     'd75qclkpf2t1uum8ij30',                       -- access: Platform Admin
     'd75qclkpf2t1uum8ij20'),                      -- role: owner
    ('d75qclkpf2t1uum8ij24',                       -- static xid for the admin member role
     NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg',                       -- tenant: Thesa
     'c2f4j7au6s7f91uqnokg',                       -- partition: Thesa (origin root)
     'd75qclkpf2t1uum8ij30',                       -- access: Platform Admin
     'd75qclkpf2t1uum8ij22')                       -- role: member
ON CONFLICT (id) DO NOTHING;
