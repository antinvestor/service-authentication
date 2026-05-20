-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: opportunities-materializer
-- Opportunities materializer. Builds derived views and aggregates
-- from raw opportunity events for downstream consumers. Operates
-- behind the queue; needs tenancy for partition scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9q40',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-opportunities_materializer',
    'opportunities-materializer',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9q4g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9q4g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9q50',
    'opportunities-materializer',
    'd86tt34pf2tddudk9q40',
    'internal',
    '{"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
