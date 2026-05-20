-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: stawi-jobs-candidates
-- Candidate matching and delivery service. Manages candidate
-- profiles, CV extraction, job matching, and match notifications.
-- Needs notification for match emails, files for CV storage,
-- redirect for tracked apply links, payment/billing for
-- subscriptions, and profile for candidate enrichment.
-- Bound to: Stawi Jobs production tenant/partition.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqdg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'sa-stawi_jobs_candidates',
    'stawi-jobs-candidates',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_billing":["*"],"service_file":["*"],"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_redirect":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqeg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqeg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'd75qclkpf2t1uum8ijhg',
    'stawi-jobs-candidates',
    'c2f4j7au6s7f91uqnqdg',
    'internal',
    '{"service_billing":["*"],"service_file":["*"],"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_redirect":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
