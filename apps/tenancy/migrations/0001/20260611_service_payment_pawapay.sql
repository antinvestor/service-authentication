-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-payment-pawapay
-- pawaPay payment provider integration. Bridges the payment service
-- to the pawaPay Merchant API v2 mobile money aggregator (MTN MoMo,
-- Airtel Money, M-Pesa, Orange Money and others) for deposit and
-- payout flows. Needs payment service for status callbacks.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd8le7qspf2t8u08dff3g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_pawapay',
    'service-payment-pawapay',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd8le7qspf2t8u08dff40',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd8le7qspf2t8u08dff40',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd8le7qspf2t8u08dff4g',
    'service-payment-pawapay',
    'd8le7qspf2t8u08dff3g',
    'internal',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
