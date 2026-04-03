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
--          └─ Client (d6qbqdkpf2t52mcunf3g)          ← Thesa dev (authorization_code)
--
-- Service account clients + service_accounts are seeded in:
--   20260306_seed_service_accounts_production.sql
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
