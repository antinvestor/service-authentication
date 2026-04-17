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
-- STAGING TENANT: Stawi Jobs Development
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Stawi Jobs Development) — child of Thesa (origin)
--     └─ Partition (Stawi Jobs Development)             ← the "home" partition
--          └─ Client (stawi-jobs-web-dev)               ← public, for user login (authorization_code)
--
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d7gi6lkpf2t67dlsqrh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Stawi Jobs Development', 'Remote job board platform for Africa and beyond', 'staging');

-- Partition (child of Thesa origin)
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, domain, allow_auto_access, properties)
VALUES ('d7gi6lkpf2t67dlsqrhg', 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg',
        'c2f4j7au6s7f91uqnokg',                          -- parent: Thesa (origin)
        'Stawi Jobs Development', 'Remote job board platform', 'jobs-dev.stawi.org', 'true',
        '{
          "default_role": "user",
          "allow_auto_access": true,
          "support_contacts": {
            "email": "hello@stawi.jobs"
          }
        }');

-- Standard partition roles (owner, admin, member)
INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties)
VALUES
    ('d7gi6lkpf2t67dlsqri0', NOW(), NOW(), 1,
     'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg',
     'owner', false, '{"description": "Full control across all services"}'),
    ('d7gi6lkpf2t67dlsqrig', NOW(), NOW(), 1,
     'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('d7gi6ncpf2t7oh5akfqg', NOW(), NOW(), 1,
     'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Public OIDC client for Stawi Jobs Development (authorization_code + PKCE)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd7gi6ncpf2t7oh5akfr0',
    'd7gi6lkpf2t67dlsqrh0',                       -- tenant: Stawi Jobs Development
    'd7gi6lkpf2t67dlsqrhg',                        -- partition: Stawi Jobs Development
    'Stawi Jobs Development',
    'stawi-jobs-web-dev',
    'public',
    '{"types": ["authorization_code", "refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_profile": ["*"]}',
    '{"uris": ["https://jobs-dev.stawi.org/auth/callback/", "http://localhost:5170/auth/callback/"]}',
    '{"uris": ["https://jobs-dev.stawi.org/", "http://localhost:5170/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
