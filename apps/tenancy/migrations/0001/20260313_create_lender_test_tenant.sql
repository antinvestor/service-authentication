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
-- DEVELOPMENT / TEST TENANT: Ant Investor Development
-- ==========================================================================
--
-- Entity relationships:
--
--   Tenant (Ant Investor Development) — child of Thesa (origin)
--     └─ Partition (Ant Investor Development)         ← the "home" partition
--          └─ Client (d6qbqdkpf2t52mcunf6g)             ← public, for user login (authorization_code)
--
-- ==========================================================================

-- Tenant
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('d6q1aekpf2taeg5iovqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
        'Ant Investor Development', 'Default base tenant for testing and building Ant Investor', 'staging');

-- Partition (child of Thesa origin)
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('d6q1aekpf2taeg5iovr0', 'd6q1aekpf2taeg5iovqg', 'd6q1aekpf2taeg5iovr0',
        'c2f4j7au6s7f91uqnokg',                          -- parent: Thesa (origin)
        'Ant Investor Development', 'Default Ant Investor development partition', 'false',
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
    ('d6q1aekpf2taeg5iovr1', NOW(), NOW(), 1,
     'd6q1aekpf2taeg5iovqg', 'd6q1aekpf2taeg5iovr0',
     'owner', false, '{"description": "Full control across all services"}'),
    ('d6q1aekpf2taeg5iovr2', NOW(), NOW(), 1,
     'd6q1aekpf2taeg5iovqg', 'd6q1aekpf2taeg5iovr0',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('d6q1aekpf2taeg5iovr3', NOW(), NOW(), 1,
     'd6q1aekpf2taeg5iovqg', 'd6q1aekpf2taeg5iovr0',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Public client: user login via authorization_code + PKCE
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6q1aekpf2taeg5iovrg',
    'd6q1aekpf2taeg5iovqg',                       -- tenant: Ant Investor Development
    'd6q1aekpf2taeg5iovr0',                        -- partition: Ant Investor Development
    'Ant Investor Development',
    'd6qbqdkpf2t52mcunf6g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_identity": [],"service_field": [],"service_loans": [],"service_origination": [],"service_savings": [],"service_funding": [],"service_operations": [],"service_device": [],"service_profile": [],"service_file": [],"service_geolocation": []}',
    '{"uris": ["https://app-dev.antinvestor.com/auth/callback","com.antinvestor.app://auth/callback","http://localhost:5174/auth/callback"]}',
    'https://static.antinvestor.com/logo.png',
    '{"uris": ["https://app-dev.antinvestor.com/","http://localhost:5174/"]}',
    'none'
) ON CONFLICT (id) DO UPDATE SET
    audiences = EXCLUDED.audiences,
    redirect_uris = EXCLUDED.redirect_uris;
