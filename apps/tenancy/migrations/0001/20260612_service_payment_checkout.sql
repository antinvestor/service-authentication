-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-payment-checkout
-- Centralized hosted checkout page. Server-renders the payments page at
-- pay.stawi.org, exposes merchant checkout-session RPCs, executes payments
-- via the payment service prompt rails and reads/writes payer prefill
-- hints on profiles.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd8lt2gkpf2t1ql3csd1g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_checkout',
    'service-payment-checkout',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd8lt2gkpf2t1ql3csd20',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd8lt2gkpf2t1ql3csd20',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd8lt2gkpf2t1ql3csd2g',
    'service-payment-checkout',
    'd8lt2gkpf2t1ql3csd1g',
    'internal',
    '{"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
