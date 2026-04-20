-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: synchronise-partitions
-- CronJob that periodically syncs partition state between the
-- tenancy service and the OAuth2 provider (Hydra). No dedicated
-- profile -- uses its service account name as the identity.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes, audiences,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'c2f4j7au6s7f91uqnprg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-synchronise_partitions',
    'synchronise-partitions',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    '{"service_tenancy":["*"]}',
    'private_key_jwt',
    'c2f4j7au6s7f91uqnpsg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, profile_id,
    client_id, client_ref, type, audiences, properties
) VALUES (
    'c2f4j7au6s7f91uqnpsg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'synchronise_partitions',
    'synchronise-partitions',
    'c2f4j7au6s7f91uqnprg',
    'internal',
    '{"service_tenancy":["*"]}',
    '{}'
) ON CONFLICT (id) DO NOTHING;
