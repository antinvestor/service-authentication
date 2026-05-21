-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: operations-formstore
-- Form-storage worker (release name `operations-formstore` in the
-- operations namespace). Persists and retrieves dynamic form
-- submissions. Needs profile and tenancy for participant scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd87bdkcpf2t58bn6vag0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-operations_formstore',
    'operations-formstore',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd87bdkcpf2t58bn6vagg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd87bdkcpf2t58bn6vagg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd87bdkcpf2t58bn6vah0',
    'operations-formstore',
    'd87bdkcpf2t58bn6vag0',
    'internal',
    '{"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
