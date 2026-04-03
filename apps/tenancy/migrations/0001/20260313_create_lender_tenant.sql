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
-- PRODUCTION TENANT: Ant Investor
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Ant Investor) — child of Thesa (origin)
--     └─ Partition (Ant Investor)                    ← the "home" partition
--          └─ Client (d6qbqdkpf2t52mcunf60)            ← public, for user login (authorization_code)
--
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d6q1aekpf2taeg5iovp0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Ant Investor', 'Default base tenant for Ant Investor', 'production');

-- Partition (child of System Manager)
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d6q1aekpf2taeg5iovpg', 'd6q1aekpf2taeg5iovp0', 'd6q1aekpf2taeg5iovpg',
        'c2f4j7au6s7f91uqnokg',                          -- parent: Thesa (origin)
        'Ant Investor', 'Default Ant Investor partition to serve the masses', 'false',
        '{
          "default_role": "user",
          "support_contacts": {
            "msisdn": "+256757546244",
            "email": "info@antinvestor.com"
          }
        }');

-- Standard partition roles (owner, admin, member)
INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties)
VALUES
    ('d6q1aekpf2taeg5iovq1', NOW(), NOW(), 1,
     'd6q1aekpf2taeg5iovp0', 'd6q1aekpf2taeg5iovpg',
     'owner', false, '{"description": "Full control across all services"}'),
    ('d6q1aekpf2taeg5iovq2', NOW(), NOW(), 1,
     'd6q1aekpf2taeg5iovp0', 'd6q1aekpf2taeg5iovpg',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('d6q1aekpf2taeg5iovq3', NOW(), NOW(), 1,
     'd6q1aekpf2taeg5iovp0', 'd6q1aekpf2taeg5iovpg',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Public client: user login via authorization_code + PKCE
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6q1aekpf2taeg5iovq0',
    'd6q1aekpf2taeg5iovp0',                       -- tenant: Ant Investor
    'd6q1aekpf2taeg5iovpg',                        -- partition: Ant Investor
    'Ant Investor',
    'd6qbqdkpf2t52mcunf60',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_lender": [],"service_device": [],"service_profile": [],"service_file": [],"service_geolocation": []}',
    '{"uris": ["https://app.antinvestor.com/auth/callback","com.antinvestor.app://auth/callback","http://localhost:5174/auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["https://app.antinvestor.com/","http://localhost:5174/"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
