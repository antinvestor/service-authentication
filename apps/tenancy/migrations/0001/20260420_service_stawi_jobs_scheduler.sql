-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: stawi-jobs-scheduler
-- Job scheduling service. Manages periodic source refresh
-- scheduling, stuck variant recovery, and pipeline maintenance.
-- No outbound service calls.
-- Bound to: Stawi Jobs production tenant/partition.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqjg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'sa-stawi_jobs_scheduler',
    'stawi-jobs-scheduler',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '["*"]',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqkg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqkg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'd75qclkpf2t1uum8ijj0',
    'stawi-jobs-scheduler',
    'c2f4j7au6s7f91uqnqjg',
    'internal',
    '["*"]',
    '{}'
) ON CONFLICT (id) DO NOTHING;
