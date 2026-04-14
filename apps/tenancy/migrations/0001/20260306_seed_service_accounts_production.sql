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
-- ORIGIN ROOT service account clients + service_accounts
-- ==========================================================================
--
-- Partition: Thesa (c2f4j7au6s7f91uqnokg)
-- Tenant:    Thesa (c2f4j7au6s7f91uqnojg)
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
--
-- Profile IDs are static xids matching the profile service migration
-- (20260331_bootstrap_profiles.sql). Each profile_id becomes the `sub`
-- claim in service-to-service JWT tokens. Contacts for these profiles
-- are encrypted and linked at app startup by SeedBootstrapContacts().
--
-- Profile ID Reference:
--   d75qclkpf2t1uum8ij40  service-authentication    authentication.bot@stawi.org
--   d75qclkpf2t1uum8ij4g  service-profile            profile.bot@stawi.org
--   d75qclkpf2t1uum8ij50  service-tenancy             tenancy.bot@stawi.org
--   d75qclkpf2t1uum8ij5g  service-notification       notification.bot@stawi.org
--   d75qclkpf2t1uum8ij60  service-device              devices.bot@stawi.org
--   d75qclkpf2t1uum8ij6g  service-setting             setting.bot@stawi.org
--   d75qclkpf2t1uum8ij70  service-payment             payment.bot@stawi.org
--   d75qclkpf2t1uum8ij7g  service-payment-jenga      payment-jenga.bot@stawi.org
--   d75qclkpf2t1uum8ij80  service-ledger              ledger.bot@stawi.org
--   d75qclkpf2t1uum8ij8g  service-billing             billing.bot@stawi.org
--   d75qclkpf2t1uum8ij90  service-files               file.bot@stawi.org
--   d75qclkpf2t1uum8ij9g  service-chat-drone         chat-drone.bot@stawi.org
--   d75qclkpf2t1uum8ija0  service-chat-gateway       chat-gateway.bot@stawi.org
--   d75qclkpf2t1uum8ijag  foundry                     foundry.bot@stawi.org
--   d75qclkpf2t1uum8ijb0  gitvault                    gitvault.bot@stawi.org
--   d75qclkpf2t1uum8ijbg  trustage                    trustage.bot@stawi.org
--   d75qclkpf2t1uum8ijc0  notification-africastalking notification-africastalking.bot@stawi.org
--   d75qclkpf2t1uum8ijcg  notification-emailsmtp     notification-emailsmtp.bot@stawi.org
--
-- Fintech service profiles (see 20260413_seed_fintech_service_accounts.sql):
--   d75qclkpf2t1uum8ijdg  service-identity           identity.bot@stawi.org
--   d75qclkpf2t1uum8ije0  service-loans              loans.bot@stawi.org
--   d75qclkpf2t1uum8ijeg  service-origination        origination.bot@stawi.org
--   d75qclkpf2t1uum8ijf0  service-funding             funding.bot@stawi.org
--   d75qclkpf2t1uum8ijfg  service-savings             savings.bot@stawi.org
--   d75qclkpf2t1uum8ijg0  service-operations          operations.bot@stawi.org
--   d75qclkpf2t1uum8ijgg  service-seed                seed.bot@stawi.org
--   d75qclkpf2t1uum8ijh0  service-stawi               stawi.bot@stawi.org
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- service-authentication
-- Core identity provider. Manages OAuth2 flows, login/consent,
-- and token issuance. Needs profile CRUD for user provisioning,
-- device access for MFA, and notification for verification emails.
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
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","access_manage","access_view","client_view","client_manage"]}',
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
    'd75qclkpf2t1uum8ij40',                           -- profile: service-authentication (authentication.bot@stawi.org)
    'service-authentication',
    'c2f4j7au6s7f91uqnoog',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","access_manage","access_view","client_view","client_manage"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-profile
-- User profile and contact management. Needs device service for
-- linking profiles to devices, notification for welcome messages,
-- and tenancy for partition/tenant lookups.
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
    'd75qclkpf2t1uum8ij4g',                           -- profile: service-profile (profile.bot@stawi.org)
    'service-profile',
    'c2f4j7au6s7f91uqnopg',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-tenancy
-- Partition, tenant, and access management. Needs notification
-- for sending invitations and profile for user provisioning
-- during access grants.
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
    'd75qclkpf2t1uum8ij50',                           -- profile: service-tenancy (tenancy.bot@stawi.org)
    'service-tenancy',
    'c2f4j7au6s7f91uqnorg',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification
-- Notification dispatch (email, SMS, push). Needs profile for
-- recipient lookup, settings for template/provider config, and
-- tenancy for partition-scoped routing.
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
    'd75qclkpf2t1uum8ij5g',                           -- profile: service-notification (notification.bot@stawi.org)
    'service-notification',
    'c2f4j7au6s7f91uqnotg',
    'internal',
    '{"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-device
-- Device registry and management. Tracks user devices for push
-- notifications and MFA. Needs profile for owner lookup,
-- notification for device alerts, and tenancy for scoping.
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
    'd75qclkpf2t1uum8ij60',                           -- profile: service-device (devices.bot@stawi.org)
    'service-device',
    'c2f4j7au6s7f91uqnovg',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-settings
-- Application configuration store. Manages key-value settings
-- scoped by module, object, and language. Needs profile, device,
-- notification, and tenancy for cross-service config reads.
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
    'd75qclkpf2t1uum8ij6g',                           -- profile: service-setting (setting.bot@stawi.org)
    'service-settings',
    'c2f4j7au6s7f91uqnp1g',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-payment
-- Payment processing engine. Orchestrates payment flows via
-- provider integrations. Needs ledger for double-entry accounting,
-- notification for payment receipts, and profile/tenancy for scoping.
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
    'd75qclkpf2t1uum8ij70',                           -- profile: service-payment (payment.bot@stawi.org)
    'service-payment',
    'c2f4j7au6s7f91uqnp3g',
    'internal',
    '{"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-payment-jenga
-- Jenga API payment provider integration. Bridges the payment
-- service to Equity Bank's Jenga API for mobile money and bank
-- transfers. Needs payment service for status callbacks.
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
    'd75qclkpf2t1uum8ij7g',                           -- profile: service-payment-jenga (payment-jenga.bot@stawi.org)
    'service-payment-jenga',
    'c2f4j7au6s7f91uqnp5g',
    'internal',
    '{"service_notification": ["notification_send"],"service_payment": ["payment_send","payment_receive","payment_status_view","payment_status_update"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-ledger
-- Double-entry accounting ledger. Manages accounts, transactions,
-- and journal entries. Needs notification for balance alerts and
-- profile/tenancy for scoping.
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
    'd75qclkpf2t1uum8ij80',                           -- profile: service-ledger (ledger.bot@stawi.org)
    'service-ledger',
    'c2f4j7au6s7f91uqnp7g',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-billing
-- Subscription and invoice management. Charges customers via
-- the payment service and records entries in the ledger.
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
    'd75qclkpf2t1uum8ij8g',                           -- profile: service-billing (billing.bot@stawi.org)
    'service-billing',
    'c2f4j7au6s7f91uqnp9g',
    'internal',
    '{"service_ledger": ["account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_payment": ["payment_send","payments_search","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-files
-- File storage and OCR processing. Manages uploads, property
-- documents, and text extraction. Needs profile for ownership
-- tracking and tenancy for scoping.
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
    'd75qclkpf2t1uum8ij90',                           -- profile: service-file (file.bot@stawi.org)
    'service-files',
    'c2f4j7au6s7f91uqnpbg',
    'internal',
    '{"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-chat-drone
-- Chat bot worker. Processes messages and executes automated
-- responses. Needs device for push delivery, notification for
-- alerts, and profile/tenancy for user context.
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
    'd75qclkpf2t1uum8ij9g',                           -- profile: service-chat-drone (chat-drone.bot@stawi.org)
    'service-chat-drone',
    'c2f4j7au6s7f91uqnpdg',
    'internal',
    '{"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-chat-gateway
-- Chat gateway. Routes messages between users and chat drones.
-- Full chat access plus device/notification/profile for delivery.
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
    'd75qclkpf2t1uum8ija0',                           -- profile: service-chat-gateway (chat-gateway.bot@stawi.org)
    'service-chat-gateway',
    'c2f4j7au6s7f91uqnpfg',
    'internal',
    '{"service_chat": ["*"],"service_device": ["*"],"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- foundry
-- Platform provisioning service. Creates and configures new
-- partitions/tenants. Needs partition_manage for full CRUD and
-- profile_create for initial admin user setup.
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
    'd75qclkpf2t1uum8ijag',                           -- profile: foundry (foundry.bot@stawi.org)
    'foundry',
    'c2f4j7au6s7f91uqnphg',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create"],"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- gitvault
-- Git repository hosting and access management. Stores code
-- artifacts and manages repository permissions. Needs profile
-- for author identity and tenancy for org scoping.
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
    'd75qclkpf2t1uum8ijb0',                           -- profile: gitvault (gitvault.bot@stawi.org)
    'gitvault',
    'c2f4j7au6s7f91uqnpjg',
    'internal',
    '{"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- trustage
-- Trust and escrow management. Handles held funds and conditional
-- releases. Needs notification for status updates and profile/
-- tenancy for participant identity.
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
    'd75qclkpf2t1uum8ijbg',                           -- profile: trustage (trustage.bot@stawi.org)
    'trustage',
    'c2f4j7au6s7f91uqnplg',
    'internal',
    '{"service_notification": ["notification_send"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification-integration-africastalking
-- Africastalking SMS/USSD provider integration. Delivers
-- notifications via Africastalking APIs and reports delivery
-- status back to the notification service.
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
    'd75qclkpf2t1uum8ijc0',                           -- profile: notification-africastalking (notification-africastalking.bot@stawi.org)
    'service-notification-integration-africastalking',
    'c2f4j7au6s7f91uqnpng',
    'internal',
    '{"service_notification": ["notification_status_update","notification_release"],"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification-integration-emailsmtp
-- Email SMTP provider integration. Delivers notifications via
-- SMTP and reports delivery status back to the notification
-- service. Uses settings for SMTP server configuration.
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
    'd75qclkpf2t1uum8ijcg',                           -- profile: notification-emailsmtp (notification-emailsmtp.bot@stawi.org)
    'service-notification-integration-emailsmtp',
    'c2f4j7au6s7f91uqnppg',
    'internal',
    '{"service_notification": ["notification_status_update","notification_release"],"service_profile": ["profile_view"],"service_setting": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- synchronise-partitions
-- CronJob that periodically syncs partition state between the
-- tenancy service and the OAuth2 provider (Hydra). No dedicated
-- profile — uses its service account name as the identity.
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
    'synchronise_partitions',                          -- no dedicated profile (CronJob utility)
    'synchronise-partitions',
    'c2f4j7au6s7f91uqnprg',
    'internal',
    '{"service_tenancy": ["partition_view","tenant_view","partition_manage"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
