-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service-notification-emailsmtp
-- Email SMTP provider integration. Delivers notifications via
-- SMTP and reports delivery status back to the notification
-- service. Uses settings for SMTP server configuration.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnppg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_emailsmtp',
    'service-notification-integration-emailsmtp',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_notification":["*"],"service_profile":["*"],"service_setting":["*"],"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpqg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpqg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'd75qclkpf2t1uum8ijcg',
    'service-notification-integration-emailsmtp',
    'c2f4j7au6s7f91uqnppg',
    'internal',
    '{"service_notification":["*"],"service_profile":["*"],"service_setting":["*"],"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
