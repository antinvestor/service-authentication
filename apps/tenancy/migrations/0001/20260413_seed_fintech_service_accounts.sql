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
-- FINTECH service account clients + service_accounts
-- ==========================================================================
--
-- Partition: Thesa (c2f4j7au6s7f91uqnokg)
-- Tenant:    Thesa (c2f4j7au6s7f91uqnojg)
--
-- Adds Client + ServiceAccount pairs for all fintech-domain services.
-- See 20260306_seed_service_accounts_production.sql for the pattern.
--
-- Profile ID Reference (fintech services):
--   d75qclkpf2t1uum8ijdg  service-identity       identity.bot@stawi.org
--   d75qclkpf2t1uum8ije0  service-loans           loans.bot@stawi.org
--   d75qclkpf2t1uum8ijf0  service-funding          funding.bot@stawi.org
--   d75qclkpf2t1uum8ijfg  service-savings          savings.bot@stawi.org
--   d75qclkpf2t1uum8ijg0  service-operations       operations.bot@stawi.org
--   d75qclkpf2t1uum8ijgg  service-seed             seed.bot@stawi.org
--   d75qclkpf2t1uum8ijh0  service-stawi            stawi.bot@stawi.org
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- service-identity
-- Identity verification and KYC management. Serves both the
-- identity and field namespaces. Manages organizations, branches,
-- agents, system users, and borrowers. Needs profile for user
-- lookup, tenancy for partition/access scoping, and notification
-- for verification workflows.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnptg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_identity',
    'service-identity',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit": ["audit_create"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","tenant_view","access_manage","access_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpug',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpug',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijdg',                           -- profile: service-identity (identity.bot@stawi.org)
    'service-identity',
    'c2f4j7au6s7f91uqnptg',
    'internal',
    '{"service_audit": ["audit_create"],"service_notification": ["notification_send"],"service_profile": ["profile_view","profile_create","profile_update","contact_manage"],"service_tenancy": ["partition_view","tenant_view","access_manage","access_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-loans
-- Loan lifecycle management. Handles loan accounts, disbursements,
-- repayments, penalties, restructuring, and collections. Calls
-- origination for application data, operations for transfers,
-- funding for fund allocation, and notification for borrower alerts.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnpvg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_loans',
    'service-loans',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit": ["audit_create"],"service_field": ["*"],"service_funding": ["*"],"service_identity": ["*"],"service_notification": ["notification_send"],"service_operations": ["*"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq0g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq0g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ije0',                           -- profile: service-loans (loans.bot@stawi.org)
    'service-loans',
    'c2f4j7au6s7f91uqnpvg',
    'internal',
    '{"service_audit": ["audit_create"],"service_field": ["*"],"service_funding": ["*"],"service_identity": ["*"],"service_notification": ["notification_send"],"service_operations": ["*"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-funding
-- Loan fund management and disbursement. Manages investor accounts
-- and fund allocation. Heavy cross-service dependency: calls
-- identity/field for borrower data, loans for account linkage and
-- loan request context, ledger for accounting entries,
-- payment for disbursement execution, operations for transfers,
-- notification for alerts, and profile/tenancy for scoping.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq3g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_funding',
    'service-funding',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit": ["audit_create"],"service_field": ["*"],"service_identity": ["*"],"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_loans": ["*"],"service_notification": ["notification_send"],"service_operations": ["*"],"service_payment": ["payment_send","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq4g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq4g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijf0',                           -- profile: service-funding (funding.bot@stawi.org)
    'service-funding',
    'c2f4j7au6s7f91uqnq3g',
    'internal',
    '{"service_audit": ["audit_create"],"service_field": ["*"],"service_identity": ["*"],"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_loans": ["*"],"service_notification": ["notification_send"],"service_operations": ["*"],"service_payment": ["payment_send","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-savings
-- Savings account management. Handles savings products, accounts,
-- deposits, withdrawals, and interest calculations. Calls
-- operations for transfer execution.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq5g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_savings',
    'service-savings',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit": ["audit_create"],"service_identity": ["*"],"service_operations": ["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq6g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq6g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijfg',                           -- profile: service-savings (savings.bot@stawi.org)
    'service-savings',
    'c2f4j7au6s7f91uqnq5g',
    'internal',
    '{"service_audit": ["audit_create"],"service_identity": ["*"],"service_operations": ["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-operations
-- Operational utilities and transfer execution. Orchestrates
-- fund transfers between accounts. Calls identity/field for
-- agent/borrower data, ledger for accounting entries, payment
-- for execution, notification for alerts, and profile/tenancy
-- for scoping.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq7g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_operations',
    'service-operations',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_audit": ["audit_create"],"service_field": ["*"],"service_identity": ["*"],"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_payment": ["payment_send","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnq8g',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnq8g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijg0',                           -- profile: service-operations (operations.bot@stawi.org)
    'service-operations',
    'c2f4j7au6s7f91uqnq7g',
    'internal',
    '{"service_audit": ["audit_create"],"service_field": ["*"],"service_identity": ["*"],"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_notification": ["notification_send"],"service_payment": ["payment_send","payment_status_view"],"service_profile": ["profile_view"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-seed
-- Direct-to-client lending service. Manages credit profiles,
-- tiers, and loan requests. Composes origination, loans, and
-- operations for end-to-end loan workflows. Calls identity/field
-- for borrower data and tenancy for partition scoping.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnq9g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_seed',
    'service-seed',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_field": ["*"],"service_identity": ["*"],"service_loans": ["*"],"service_operations": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqag',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqag',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijgg',                           -- profile: service-seed (seed.bot@stawi.org)
    'service-seed',
    'c2f4j7au6s7f91uqnq9g',
    'internal',
    '{"service_field": ["*"],"service_identity": ["*"],"service_loans": ["*"],"service_operations": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-stawi
-- Stawi workflow orchestration. Composes the full fintech stack
-- for end-to-end lending workflows (USSD/API). Calls identity/
-- field for borrower and agent data, origination for applications,
-- loans for accounts, savings for deposits, ledger for balances,
-- payment for disbursement/collection, notification for SMS/push,
-- files for document handling, and profile/tenancy for scoping.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqbg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_stawi',
    'service-stawi',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_field": ["*"],"service_file": ["*"],"service_identity": ["*"],"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_loans": ["*"],"service_notification": ["notification_send"],"service_operations": ["*"],"service_payment": ["payment_send","payment_status_view"],"service_profile": ["profile_view"],"service_savings": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqcg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqcg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijh0',                           -- profile: service-stawi (stawi.bot@stawi.org)
    'service-stawi',
    'c2f4j7au6s7f91uqnqbg',
    'internal',
    '{"service_field": ["*"],"service_file": ["*"],"service_identity": ["*"],"service_ledger": ["account_manage","account_view","transaction_create","transaction_view"],"service_loans": ["*"],"service_notification": ["notification_send"],"service_operations": ["*"],"service_payment": ["payment_send","payment_status_view"],"service_profile": ["profile_view"],"service_savings": ["*"],"service_tenancy": ["partition_view","tenant_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
