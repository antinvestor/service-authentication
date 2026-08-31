-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: imports
-- Stawi Imports API (stawi-importation-sales Cloud Run imports); owns permission namespace service_imports; calls tenancy (permission registration) and profile.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'daaltq4pf2tb6me3uap0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-imports',
    'imports',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'daaltq4pf2tb6me3uaq0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'daaltq4pf2tb6me3uaq0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'imports',
    'daalssspf2tbp6p7ekrg',
    'imports',
    'daaltq4pf2tb6me3uap0',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daaltq4pf2tb7p83vshg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uap0', 'https://api.stawi.org/profile') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daaltq4pf2tb7p83vsi0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uap0', 'https://api.stawi.org/tenancy') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES ('daaltq4pf2tb6me3uaqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uaq0', 1, 1, 0, 'pending', 0) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daaltq4pf2tb7p83vsig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uaqg', 'service_imports', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'acquisition_authorize') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'analytics_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsk0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'orders_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vskg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'orders_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsl0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'payments_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vslg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'payments_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsm0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'payments_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'quotes_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsn0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'quotes_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'quotes_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vso0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'requests_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsog', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'requests_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsp0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'transactions_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vspg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'transactions_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsq0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'vehicles_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'vehicles_delete') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'vehicles_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaltq4pf2tb7p83vsrg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb7p83vsig', 'vehicles_view') ON CONFLICT (id) DO NOTHING;

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'imports';
