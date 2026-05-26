-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-authentication
-- Core identity provider. Manages OAuth2 flows, login/consent,
-- and token issuance. Needs profile CRUD for user provisioning,
-- device access for MFA, notification for verification emails, and
-- files for async avatar import from external IdPs (added in 59728b4).

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnoog',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_authentication',
    'service-authentication',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device":["*"],"service_file":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnolg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnolg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ij40',
    'service-authentication',
    'c2f4j7au6s7f91uqnoog',
    'internal',
    '{"service_device":["*"],"service_file":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
