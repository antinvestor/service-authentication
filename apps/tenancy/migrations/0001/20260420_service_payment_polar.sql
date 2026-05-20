-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-payment-polar
-- Polar payment provider integration. Bridges the payment service
-- to Polar's checkout/billing API for digital-product flows. Needs
-- payment service for status callbacks.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9ppg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_polar',
    'service-payment-polar',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9pq0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9pq0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9pqg',
    'service-payment-polar',
    'd86tt34pf2tddudk9ppg',
    'internal',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
