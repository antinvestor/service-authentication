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
-- SYSTEM OPERATIONS PARTITION + OPENOBSERVE CLIENT
-- ==========================================================================
--
-- A dedicated partition for system-level operational tooling (observability,
-- monitoring, etc.) under the Thesa root partition.
--
-- Entity relationships:
--
--   Tenant (Thesa — origin, existing)
--     └─ Partition (System Operations)                ← new, child of Thesa
--          ├─ Client (0jofrmbj6lno69ui68t8)               ← public, authorization_code (OpenObserve)
--          └─ PartitionRole (owner, admin, member)      ← standard role set
--
-- ==========================================================================

-- Partition (child of Thesa root)
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('0u8j5eensusgkfnc9n4k', 'c2f4j7au6s7f91uqnojg', '0u8j5eensusgkfnc9n4k',
        'c2f4j7au6s7f91uqnokg',                          -- parent: Thesa (origin root)
        'System Operations', 'Partition for system-level operational tooling (observability, monitoring)', 'false',
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
    ('1n7uumiq2e49r1gkghsu', NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg', '0u8j5eensusgkfnc9n4k',
     'owner', false, '{"description": "Full control across all services"}'),
    ('1ulj4c02bdmtks4enjvb', NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg', '0u8j5eensusgkfnc9n4k',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('1c9cq13lh23dmc0p1s80', NOW(), NOW(), 1,
     'c2f4j7au6s7f91uqnojg', '0u8j5eensusgkfnc9n4k',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Public client: OpenObserve — user login via authorization_code + PKCE
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    '1fqif38qjjise0msbtq3',
    'c2f4j7au6s7f91uqnojg',                       -- tenant: Thesa
    '0u8j5eensusgkfnc9n4k',                        -- partition: System Operations
    'OpenObserve',
    '0jofrmbj6lno69ui68t8',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access',
    '{}',
    '{"uris": ["https://observe.stawi.org/web/cb"]}',
    '',
    '{"uris": ["https://observe.stawi.org/"]}',
    'none'
) ON CONFLICT (id) DO UPDATE SET
    audiences = EXCLUDED.audiences,
    redirect_uris = EXCLUDED.redirect_uris;
