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
-- PRODUCTION service account clients + service_accounts
-- ==========================================================================
--
-- Partition: System Manager (c2f4j7au6s7f91uqnokg)
-- Tenant:    System Manager (c2f4j7au6s7f91uqnojg)
--
-- Each service gets a Client + ServiceAccount pair:
--
--   Client (type=internal, grant=client_credentials)
--     │
--     │  client_ref (FK → Client.id)
--     ▼
--   ServiceAccount (profile_id = subject in tokens)
--
-- The Client defines the OAuth2 credentials (client_id/secret, scopes).
-- The ServiceAccount links the Client to a profile identity and records
-- which partition/tenant it belongs to.
--
-- All service accounts use private_key_jwt authentication (no client_secret).
-- Services authenticate via JWT signed with their private key.
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- service-authentication
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnoog',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_authentication',
    'service-authentication',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contacts_manage"],"service_tenancy": ["partition_view","access_manage","access_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnolg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnolg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_authentication',
    'service-authentication',
    'c2f4j7au6s7f91uqnoog',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contacts_manage"],"service_tenancy": ["partition_view","access_manage","access_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-profile
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnopg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_profile',
    'service-profile',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnoqg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnoqg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_profile',
    'service-profile',
    'c2f4j7au6s7f91uqnopg',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-tenancy
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnorg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_tenancy',
    'service-tenancy',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnosg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnosg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_tenancy',
    'service-tenancy',
    'c2f4j7au6s7f91uqnorg',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnotg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification',
    'service-notification',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnoug',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnoug',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification',
    'service-notification',
    'c2f4j7au6s7f91uqnotg',
    'internal',
    '{"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-device
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnovg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_device',
    'service-device',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnp0g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp0g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_device',
    'service-device',
    'c2f4j7au6s7f91uqnovg',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-settings
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnp1g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_setting',
    'service-settings',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnp2g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp2g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_setting',
    'service-settings',
    'c2f4j7au6s7f91uqnp1g',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-payment
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnp3g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment',
    'service-payment',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnp4g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp4g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_payment',
    'service-payment',
    'c2f4j7au6s7f91uqnp3g',
    'internal',
    '{"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-payment-jenga
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnp5g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_jenga',
    'service-payment-jenga',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_send"],"service_payment": ["payment_send","payment_receive","payment_status_view","payment_status_update"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnp6g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp6g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_payment_jenga',
    'service-payment-jenga',
    'c2f4j7au6s7f91uqnp5g',
    'internal',
    '{"service_notification": ["notification_send"],"service_payment": ["payment_send","payment_receive","payment_status_view","payment_status_update"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-ledger
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnp7g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_ledger',
    'service-ledger',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnp8g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp8g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_ledger',
    'service-ledger',
    'c2f4j7au6s7f91uqnp7g',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-billing
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnp9g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_billing',
    'service-billing',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_ledger": ["account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_payment": ["payment_send","payments_search","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpag',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpag',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_billing',
    'service-billing',
    'c2f4j7au6s7f91uqnp9g',
    'internal',
    '{"service_ledger": ["account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_payment": ["payment_send","payments_search","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-files
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpbg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_file',
    'service-files',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpcg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpcg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_file',
    'service-files',
    'c2f4j7au6s7f91uqnpbg',
    'internal',
    '{"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-chat-drone
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpdg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_chat_drone',
    'service-chat-drone',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpeg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpeg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_chat_drone',
    'service-chat-drone',
    'c2f4j7au6s7f91uqnpdg',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-chat-gateway
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpfg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_chat_gateway',
    'service-chat-gateway',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_chat": ["*"],"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpgg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpgg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_chat_gateway',
    'service-chat-gateway',
    'c2f4j7au6s7f91uqnpfg',
    'internal',
    '{"service_chat": ["*"],"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- foundry
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnphg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-foundry',
    'foundry',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"],"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpig',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpig',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'foundry',
    'foundry',
    'c2f4j7au6s7f91uqnphg',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"],"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- gitvault
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpjg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-gitvault',
    'gitvault',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpkg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpkg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'gitvault',
    'gitvault',
    'c2f4j7au6s7f91uqnpjg',
    'internal',
    '{"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- trustage
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnplg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-trustage',
    'trustage',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpmg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpmg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'trustage',
    'trustage',
    'c2f4j7au6s7f91uqnplg',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification-integration-africastalking
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpng',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_africastalking',
    'service-notification-integration-africastalking',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_status_update","notification_release"],"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpog',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpog',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification_africastalking',
    'service-notification-integration-africastalking',
    'c2f4j7au6s7f91uqnpng',
    'internal',
    '{"service_notification": ["notification_status_update","notification_release"],"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification-integration-emailsmtp
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnppg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_emailsmtp',
    'service-notification-integration-emailsmtp',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification": ["notification_status_update","notification_release"],"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpqg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpqg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification_emailsmtp',
    'service-notification-integration-emailsmtp',
    'c2f4j7au6s7f91uqnppg',
    'internal',
    '{"service_notification": ["notification_status_update","notification_release"],"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- synchronise-partitions (CronJob for periodic tenancy sync)
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnprg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-synchronise_partitions',
    'synchronise-partitions',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpsg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpsg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'synchronise_partitions',
    'synchronise-partitions',
    'c2f4j7au6s7f91uqnprg',
    'internal',
    '{"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

