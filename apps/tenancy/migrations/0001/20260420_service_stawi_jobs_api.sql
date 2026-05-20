-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: stawi-jobs-api
-- Public job search API. Serves the jobs.stawi.org frontend with
-- full-text search, filtering, and job detail endpoints. Read-only
-- access to the jobs database. No outbound service calls.
-- Bound to: Stawi Jobs production tenant/partition.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqhg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'sa-stawi_jobs_api',
    'stawi-jobs-api',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqig',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqig',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'd75qclkpf2t1uum8ijig',
    'stawi-jobs-api',
    'c2f4j7au6s7f91uqnqhg',
    'internal',
    '{}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
