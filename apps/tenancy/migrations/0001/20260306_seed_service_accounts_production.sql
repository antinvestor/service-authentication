-- ==========================================================================
-- PRODUCTION service account clients + service_accounts
-- ==========================================================================
--
-- Partition: System Manager (c2f4j7au6s7f91uqnokg)
-- Tenant:    System Manager (c2f4j7au6s7f91uqnojg)
--
-- Each service gets a Client + ServiceAccount pair:
--
--   Client (type=internal, grant=client_credentials)
--     │
--     │  client_ref (FK → Client.id)
--     ▼
--   ServiceAccount (profile_id = subject in tokens)
--
-- The Client defines the OAuth2 credentials (client_id/secret, scopes).
-- The ServiceAccount links the Client to a profile identity and records
-- which partition/tenant it belongs to.
--
-- NOTE: client_id and client_secret values are aligned to production cluster
-- colony deployments and oauth2-cli secrets as of 2026-03-06.
-- ==========================================================================

-- ──────────────────────────────────────────────────────────────
-- service-authentication
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnoog',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_authentication',
    'service-authentication',
    'ITvdpoRNMyVyqjQnQ23ytKKJxygLB5HnKGejCArawbGlAYiU',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy","service_devices"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnolg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnolg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_authentication',
    'service-authentication',
    'c2f4j7au6s7f91uqnoog',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-profile
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnopg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_profile',
    'service-profile',
    'Vi2B9Ed0f6l8NZrCXC27sOxUo0SMH7wH4P73vfFFSSiwF6t2',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_tenancy","service_devices"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnoqg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnoqg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_profile',
    'service-profile',
    'c2f4j7au6s7f91uqnopg',
    'internal',
    '{"namespaces": ["service_notifications","service_tenancy","service_devices"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-tenancy
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnorg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_tenancy',
    'service-tenancy',
    'AD0XjiHRrS4io7qrJeubs2Ja8ievgifqs3mqbjaJtMld0dra',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnosg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnosg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_tenancy',
    'service-tenancy',
    'c2f4j7au6s7f91uqnorg',
    'internal',
    '{"namespaces": ["service_notifications","service_profile"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnotg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notifications',
    'service-notification',
    'RkOYfbMlbmkWJvgL0rgy1ctrS6GcNqqcHMfXxfxQBvajd1zt',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnoug'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnoug',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notifications',
    'service-notification',
    'c2f4j7au6s7f91uqnotg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-devices
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnovg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_devices',
    'service-devices',
    'ZUDE1sHQYjnw32x1ERpRl3P7hnuGMt94MJ6MUhmDgqXRZgEB',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile","service_device"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnp0g'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp0g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_devices',
    'service-devices',
    'c2f4j7au6s7f91uqnovg',
    'internal',
    '{"namespaces": ["service_notifications","service_profile","service_device"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-settings
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnp1g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_settings',
    'service-settings',
    'BwVET6DQzzz9aHsc6nE6QroFwLo8M0obpEKHMK9NSar3BqYd',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile","service_device"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnp2g'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp2g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_settings',
    'service-settings',
    'c2f4j7au6s7f91uqnp1g',
    'internal',
    '{"namespaces": ["service_notifications","service_profile","service_device"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-payment
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnp3g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment',
    'service-payment',
    'Xy7CgD9JVAjy8ITai90jkIJGY49cV1wvDsNqFzw0JJ6T7HaI',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnp4g'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp4g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_payments',
    'service-payment',
    'c2f4j7au6s7f91uqnp3g',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-payment-jenga
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnp5g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_jenga',
    'service-payment-jenga',
    'zOrn1UmlV42GsH6EKnhOEjhvsQvLDlqbyYYxQxzQhJcLVL62',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnp6g'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp6g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_payments_jenga',
    'service-payment-jenga',
    'c2f4j7au6s7f91uqnp5g',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-ledger
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnp7g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_ledger',
    'service-ledger',
    '13638BAsNT1PhaUuLeQcwUwQBMpzjZm3yVEZyVBUj3EW8xxX',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnp8g'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnp8g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_ledger',
    'service-ledger',
    'c2f4j7au6s7f91uqnp7g',
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-billing
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnp9g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_billing',
    'service-billing',
    '1fdd689105f3d183e49173db0f2ba5f0beb5bdc32a78199f8c42f0c9026c7da29f111209a2f6a14be8793ffd58ff719c',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpag'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpag',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_billing',
    'service-billing',
    'c2f4j7au6s7f91uqnp9g',
    'internal',
    '{"namespaces": ["service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-files
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnpbg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_files',
    'service-files',
    'VeQdjjgfPHVPbYCbgyUHpNcshHe00dMRtWl0zZ9kO3v9R2uk',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpcg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpcg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_files',
    'service-files',
    'c2f4j7au6s7f91uqnpbg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-chat-drone
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnpdg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_chat_drone',
    'service-chat-drone',
    'S3ufOQAjErZfl3Edvva37uiTzgkKBIL4wOJofw8fEnxvk0Cf',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_profile","service_device"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpeg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpeg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_chat_drone',
    'service-chat-drone',
    'c2f4j7au6s7f91uqnpdg',
    'internal',
    '{"namespaces": ["service_notifications","service_profile","service_device"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-chat-gateway
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnpfg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_chat_gateway',
    'service-chat-gateway',
    '9150M2z7251RKppAUAx0CWYkb2SXQkiw17PdPtPkYE18iaYU',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_notifications","service_chat_drone","service_device"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpgg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpgg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_chat_gateway',
    'service-chat-gateway',
    'c2f4j7au6s7f91uqnpfg',
    'internal',
    '{"namespaces": ["service_notifications","service_chat_drone","service_device"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- foundry
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnphg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-foundry',
    'foundry',
    'iTJlenYyGj9HMKiYGSpq7bjKqT89A3n6GfIyQbjpE9osMEv2',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpig'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpig',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'foundry',
    'foundry',
    'c2f4j7au6s7f91uqnphg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- gitvault
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnpjg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-gitvault',
    'gitvault',
    'A6AFkzTXkuHdtvKgKs8nlrSPO3WTzLc4Ml8f02XCmeFyg6UN',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpkg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpkg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'gitvault',
    'gitvault',
    'c2f4j7au6s7f91uqnpjg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- trustage
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnplg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-trustage',
    'trustage',
    'y0Pkcb~ytMQuaxb887V.Zau4yB',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpmg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpmg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'trustage',
    'trustage',
    'c2f4j7au6s7f91uqnplg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification-integration-africastalking
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnpng',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_africastalking',
    'service-notification-integration-africastalking',
    'HJ8hx0WrPK07gBLY1d2aTtACuUK8XS1Dvb4DbdBPT5gOouuU',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_settings"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpog'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpog',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification_africastalking',
    'service-notification-integration-africastalking',
    'c2f4j7au6s7f91uqnpng',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_settings"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- ──────────────────────────────────────────────────────────────
-- service-notification-integration-emailsmtp
-- ──────────────────────────────────────────────────────────────
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences, token_endpoint_auth_method, service_account_id
) VALUES (
    'c2f4j7au6s7f91uqnppg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_emailsmtp',
    'service-notification-integration-emailsmtp',
    'N7I3wbPza84IYi0I0gI4qreKak9tERGdqapHiUN3BFgS5Uyw',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_settings"]}',
    'client_secret_post',
    'c2f4j7au6s7f91uqnpqg'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpqg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification_emailsmtp',
    'service-notification-integration-emailsmtp',
    'c2f4j7au6s7f91uqnppg',
    'internal',
    '{"namespaces": ["service_profile","service_tenancy","service_notifications","service_settings"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
