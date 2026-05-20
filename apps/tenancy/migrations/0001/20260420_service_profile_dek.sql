-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-profile-dek
-- Profile DEK (Data Encryption Key) worker. Runs alongside the
-- main profile service to manage field-level encryption keys.
-- Needs notification for key-rotation events, device for trusted
-- key delivery, and tenancy for partition scoping.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9pjg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_profile_dek',
    'service-profile-dek',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_device":["*"],"service_notification":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9pk0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9pk0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9pkg',
    'service-profile-dek',
    'd86tt34pf2tddudk9pjg',
    'internal',
    '{"service_device":["*"],"service_notification":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
