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
-- PRODUCTION TENANT: Stawi Jobs
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Stawi Jobs) — child of Thesa (origin)
--     └─ Partition (Stawi Jobs)                         ← the "home" partition
--          └─ Client (stawi-jobs-web)                   ← public, for user login (authorization_code)
--
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d7gi6lkpf2t67dlsqre0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Stawi Jobs', 'Remote job board platform for Africa and beyond', 'production');

-- Partition (child of Thesa origin)
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, domain, allow_auto_access, properties)
VALUES ('d7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg',
        'c2f4j7au6s7f91uqnokg',                          -- parent: Thesa (origin)
        'Stawi Jobs', 'Remote job board platform', 'jobs.stawi.org', 'true',
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
    ('d7gi6lkpf2t67dlsqrf0', NOW(), NOW(), 1,
     'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg',
     'owner', false, '{"description": "Full control across all services"}'),
    ('d7gi6lkpf2t67dlsqrfg', NOW(), NOW(), 1,
     'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('d7gi6lkpf2t67dlsqrg0', NOW(), NOW(), 1,
     'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Public OIDC client for Stawi Jobs (authorization_code + PKCE)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd7gi6lkpf2t67dlsqrgg',
    'd7gi6lkpf2t67dlsqre0',                       -- tenant: Stawi Jobs
    'd7gi6lkpf2t67dlsqreg',                        -- partition: Stawi Jobs
    'Stawi Jobs Web',
    'stawi-jobs-web',
    'public',
    '{"types": ["authorization_code", "refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_profile": ["*"]}',
    '{"uris": ["https://jobs.stawi.org/auth/callback/"]}',
    '{"uris": ["https://jobs.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
