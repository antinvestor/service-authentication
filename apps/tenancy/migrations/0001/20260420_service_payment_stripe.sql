-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-payment-stripe
-- Stripe payment provider integration. Bridges the payment service
-- to Stripe for card and SEPA flows. Needs payment service for
-- status callbacks and notification for receipt delivery.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9pr0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_stripe',
    'service-payment-stripe',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9prg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9prg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9ps0',
    'service-payment-stripe',
    'd86tt34pf2tddudk9pr0',
    'internal',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
