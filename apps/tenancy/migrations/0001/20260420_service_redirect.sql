-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-redirect
-- Short URL and link redirector. Handles tracked redirects and
-- click attribution for files/storage hand-offs. Needs profile
-- and tenancy for owner/partition scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9pdg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_redirect',
    'service-redirect',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9pe0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9pe0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9peg',
    'service-redirect',
    'd86tt34pf2tddudk9pdg',
    'internal',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
