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
-- DEV / TEST service account clients + service_accounts
-- ==========================================================================
--
-- Partition: Dev Backoffice (9bsv0s3pbdv002o80qhg)
-- Tenant:    Testing Manager (9bsv0s3pbdv002o80qfg)
--
-- These mirror the production (System Manager) service accounts so that
-- services running in dev/test environments can obtain tokens against
-- the test tenant without touching production data.
--
-- Each service gets a Client + ServiceAccount pair:
--
--   Client (type=internal, grant=client_credentials)
--     │
--     │  client_ref (FK → Client.id)
--     ▼
--   ServiceAccount (profile_id = subject in tokens)
--
-- Dev client_ids use the `dev_` prefix to distinguish from production.
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- dev_authentication_tests (integration tests against test tenant)
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'd6l82t4pf2t82gudn7vg',
    '9bsv0s3pbdv002o80qfg',                       -- tenant: Testing Manager
    '9bsv0s3pbdv002o80qhg',                        -- partition: Dev Backoffice
    'sa-authentication_tests',
    'dev_authentication_tests',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","access_manage","access_view"]}',
    'client_secret_post',
    'd6l82t4pf2t82gudn800'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn800',
    '9bsv0s3pbdv002o80qfg',                       -- tenant: Testing Manager
    '9bsv0s3pbdv002o80qhg',                        -- partition: Dev Backoffice
    'dev_authentication_tests',                     -- profile_id (subject in tokens)
    'dev_authentication_tests',                     -- client_id (denormalized for lookup)
    'd6l82t4pf2t82gudn7vg',                        -- client_ref → Client.id above
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","access_manage","access_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- dev_service_authentication
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'd6l82t4pf2t82gudn80g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_authentication',
    'dev_service_authentication',
    'vkGiJroO9dAS5eFnuaGy',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","access_manage","access_view"]}',
    'client_secret_post',
    'd6l82t4pf2t82gudn810'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn810',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_authentication',
    'dev_service_authentication',
    'd6l82t4pf2t82gudn80g',                        -- client_ref → Client.id above
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","access_manage","access_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- dev_service_profile
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'd6l82t4pf2t82gudn81g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_profile',
    'dev_service_profile',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_tenancy": ["partition_view","tenant_view"]}',
    'client_secret_post',
    'd6l82t4pf2t82gudn820'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn820',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_profile',
    'dev_service_profile',
    'd6l82t4pf2t82gudn81g',                        -- client_ref → Client.id above
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- dev_service_tenancy
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'd6l82t4pf2t82gudn82g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_tenancy',
    'dev_service_tenancy',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"dev_authentication_tests": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"]}',
    'client_secret_post',
    'd6l82t4pf2t82gudn830'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn830',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_tenancy',
    'dev_service_tenancy',
    'd6l82t4pf2t82gudn82g',                        -- client_ref → Client.id above
    'internal',
    '{"dev_authentication_tests": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- dev_service_notification
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'd6l82t4pf2t82gudn83g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_notification',
    'dev_service_notification',
    'hkGiJroO9cDS5eFnuaAV',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile": ["profile_view"],"service_settings": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    'client_secret_post',
    'd6l82t4pf2t82gudn840'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn840',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_notification',
    'dev_service_notification',
    'd6l82t4pf2t82gudn83g',                        -- client_ref → Client.id above
    'internal',
    '{"service_profile": ["profile_view"],"service_settings": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- dev_service_devices
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'd6l82t4pf2t82gudn84g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-service_devices',
    'dev_service_devices',
    'hkBaJroO9cDGleFnuaAZ',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'client_secret_post',
    'd6l82t4pf2t82gudn850'                        -- service_account_id → SA.id below
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn850',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_service_devices',
    'dev_service_devices',
    'd6l82t4pf2t82gudn84g',                        -- client_ref → Client.id above
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- dev_synchronise_partitions (CronJob for periodic tenancy sync)
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd6l82t4pf2t82gudn86g',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'sa-synchronise_partitions',
    'dev_synchronise_partitions',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    'private_key_jwt',
    'd6l82t4pf2t82gudn870',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd6l82t4pf2t82gudn870',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'dev_synchronise_partitions',
    'dev_synchronise_partitions',
    'd6l82t4pf2t82gudn86g',
    'internal',
    '{"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
