-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: opportunities-worker
-- Opportunities background worker. Processes queued jobs in the
-- opportunities pipeline (enrichment, scheduling, retries).
-- Operates behind the queue; needs tenancy for partition scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9q5g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-opportunities_worker',
    'opportunities-worker',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9q60',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9q60',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9q6g',
    'opportunities-worker',
    'd86tt34pf2tddudk9q5g',
    'internal',
    '{"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
