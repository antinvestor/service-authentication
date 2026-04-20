-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-device
-- Device registry and management. Tracks user devices for push
-- notifications and MFA. Needs profile for owner lookup,
-- notification for device alerts, and tenancy for scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnovg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_device',
    'service-device',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnp0g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp0g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ij60',
    'service-device',
    'c2f4j7au6s7f91uqnovg',
    'internal',
    '{"service_device":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
