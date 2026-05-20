-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-fintech-identity
-- External fintech identity gateway. Public-facing identity API
-- for fintech consumers. Bridges to internal identity service and
-- needs profile/tenancy for scoping plus notification for KYC alerts.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9pgg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_fintech_identity',
    'service-fintech-identity',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_identity":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9ph0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9ph0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9phg',
    'service-fintech-identity',
    'd86tt34pf2tddudk9pgg',
    'internal',
    '{"service_identity":["*"],"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
