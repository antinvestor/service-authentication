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
-- STAWI JOBS service account clients + service_accounts
-- ==========================================================================
--
-- Partition: Thesa (c2f4j7au6s7f91uqnokg)
-- Tenant:    Thesa (c2f4j7au6s7f91uqnojg)
--
-- Adds Client + ServiceAccount pairs for all stawi-jobs services.
-- See 20260306_seed_service_accounts_production.sql for the pattern.
--
-- Profile ID Reference (stawi-jobs services):
--   d75qclkpf2t1uum8ijhg  stawi-jobs-candidates   stawi-jobs-candidates.bot@stawi.org
--   d75qclkpf2t1uum8iji0  stawi-jobs-crawler       stawi-jobs-crawler.bot@stawi.org
--   d75qclkpf2t1uum8ijig  stawi-jobs-api           stawi-jobs-api.bot@stawi.org
--   d75qclkpf2t1uum8ijj0  stawi-jobs-scheduler     stawi-jobs-scheduler.bot@stawi.org
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- stawi-jobs-candidates
-- Candidate matching and delivery service. Manages candidate
-- profiles, CV extraction, job matching, and match notifications.
-- Needs notification for match emails, files for CV storage,
-- redirect for tracked apply links, payment/billing for
-- subscriptions, and profile for candidate enrichment.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqdg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-stawi-jobs-candidates',
    'stawi-jobs-candidates',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'internal openid',
    '{"service_notification": ["notification_send"],"service_file": ["file_upload","file_download"],"service_redirect": ["link_create","link_stats"],"service_payment": ["subscription_create","subscription_status"],"service_profile": ["profile_view"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqeg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqeg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijhg',                           -- profile: stawi-jobs-candidates
    'stawi-jobs-candidates',
    'c2f4j7au6s7f91uqnqdg',
    'internal',
    '{"service_notification": ["notification_send"],"service_file": ["file_upload","file_download"],"service_redirect": ["link_create","link_stats"],"service_payment": ["subscription_create","subscription_status"],"service_profile": ["profile_view"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- stawi-jobs-crawler
-- Job crawling and pipeline service. Manages source discovery,
-- content extraction, deduplication, AI normalization, validation,
-- and canonical job creation. Internal service with no outbound
-- service-to-service calls (uses Ollama directly for AI).
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqfg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-stawi-jobs-crawler',
    'stawi-jobs-crawler',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'internal openid',
    '{}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqgg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqgg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8iji0',                           -- profile: stawi-jobs-crawler
    'stawi-jobs-crawler',
    'c2f4j7au6s7f91uqnqfg',
    'internal',
    '{}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- stawi-jobs-api
-- Public job search API. Serves the jobs.stawi.org frontend with
-- full-text search, filtering, and job detail endpoints. Read-only
-- access to the jobs database. No outbound service calls.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqhg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-stawi-jobs-api',
    'stawi-jobs-api',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'internal openid',
    '{}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqig',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqig',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijig',                           -- profile: stawi-jobs-api
    'stawi-jobs-api',
    'c2f4j7au6s7f91uqnqhg',
    'internal',
    '{}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- stawi-jobs-scheduler
-- Job scheduling service. Manages periodic source refresh
-- scheduling, stuck variant recovery, and pipeline maintenance.
-- No outbound service calls.
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqjg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-stawi-jobs-scheduler',
    'stawi-jobs-scheduler',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'internal openid',
    '{}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqkg',
    '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqkg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijj0',                           -- profile: stawi-jobs-scheduler
    'stawi-jobs-scheduler',
    'c2f4j7au6s7f91uqnqjg',
    'internal',
    '{}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
