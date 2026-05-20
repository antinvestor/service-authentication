-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: stawi-jobs-crawler
-- Job crawling and pipeline service. Manages source discovery,
-- content extraction, deduplication, AI normalization, validation,
-- and canonical job creation. Internal service with no outbound
-- service-to-service calls (uses Ollama directly for AI).
-- Bound to: Stawi Jobs production tenant/partition.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnqfg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'sa-stawi_jobs_crawler',
    'stawi-jobs-crawler',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnqgg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnqgg',
    'd7gi6lkpf2t67dlsqre0',
    'd7gi6lkpf2t67dlsqreg',
    'd75qclkpf2t1uum8iji0',
    'stawi-jobs-crawler',
    'c2f4j7au6s7f91uqnqfg',
    'internal',
    '{}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
