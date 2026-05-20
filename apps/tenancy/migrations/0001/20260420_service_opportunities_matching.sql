-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: opportunities-matching
-- Opportunities candidate-matching worker. Scores and notifies
-- candidates against opportunity listings. Needs notification for
-- alerts, file/redirect for asset hand-offs, and payment for
-- conversion-tied flows.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd86tt34pf2tddudk9q2g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-opportunities_matching',
    'opportunities-matching',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_file":["*"],"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_redirect":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'd86tt34pf2tddudk9q30',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'd86tt34pf2tddudk9q30',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd86tt34pf2tddudk9q3g',
    'opportunities-matching',
    'd86tt34pf2tddudk9q2g',
    'internal',
    '{"service_file":["*"],"service_notification":["*"],"service_payment":["*"],"service_profile":["*"],"service_redirect":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
