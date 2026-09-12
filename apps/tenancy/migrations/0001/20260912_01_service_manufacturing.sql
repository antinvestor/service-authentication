-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_manufacturing
-- Manufacturing service (antinvestor service-manufacturing on Cloud Run stawi-manufacturing). Owns permission namespace service_manufacturing; Hydra client_id service-manufacturing.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'daid3uspf2t8dfvkjnl0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_manufacturing',
    'service-manufacturing',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'daid3uspf2t8dfvkjnm0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'daid3uspf2t8dfvkjnm0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_manufacturing',
    'daid38spf2t72pqigk80',
    'service-manufacturing',
    'daid3uspf2t8dfvkjnl0',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daid3v4pf2t8dv11qcd0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3uspf2t8dfvkjnl0', 'https://api.stawi.org/profile') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daid3v4pf2t8dv11qcdg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3uspf2t8dfvkjnl0', 'https://api.stawi.org/tenancy') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES ('daid3uspf2t8dfvkjnmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3uspf2t8dfvkjnm0', 1, 1, 0, 'pending', 0) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daid3v4pf2t8dv11qce0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3uspf2t8dfvkjnmg', 'service_manufacturing', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qceg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'batch_complete') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'batch_operate') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcfg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'batch_override') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcg0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'batch_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'cleaning_perform') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qch0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'cleaning_verify') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qchg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'costing_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qci0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'costing_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'demand_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'demand_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'environment_alarm_acknowledge') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qck0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'environment_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qckg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'environment_record') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcl0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'environment_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qclg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'equipment_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcm0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'equipment_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inspection_override') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcn0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inspection_perform') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inspection_template_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qco0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inspection_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcog', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inventory_adjust') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcp0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inventory_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcpg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'inventory_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcq0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'label_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'maintenance_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'plan_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcrg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'plan_validate') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcs0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'plan_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcsg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'recall_initiate') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qct0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'recall_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qctg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'recall_resolve') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcu0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'recipe_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'recipe_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcv0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'shelf_life_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qcvg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'shelf_life_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qd00', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'trace_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qd0g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'waste_dispose') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qd10', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'waste_record') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daid3v4pf2t8dv11qd1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daid3v4pf2t8dv11qce0', 'waste_view') ON CONFLICT (id) DO NOTHING;
