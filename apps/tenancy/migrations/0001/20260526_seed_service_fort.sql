-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-fort
-- Email control plane. Manages inbound email processing and
-- routing. Needs profile for sender identity, tenancy for
-- multi-tenant scoping, and notification for delivery.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd8as62bvfo145u8bon3g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_fort',
    'service-fort',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd8as62fieol45uar4okg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd8as62fieol45uar4okg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd8as6297jdi45ufqlh70',
    'service-fort',
    'd8as62bvfo145u8bon3g',
    'internal',
    '{"service_notification":["*"],"service_profile":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
