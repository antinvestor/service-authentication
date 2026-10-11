-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_settlement
-- Stawi settlement (stawilabs/stawi apps/settlement, HelmRelease settlement in namespace stawi). Owns permission namespace service_settlement; Hydra client_id settlement (colony uses the release name).

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'db5iu14pf2t15n40lj2g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_settlement',
    'settlement',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'db5iu14pf2t15n40lj30',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'db5iu14pf2t15n40lj30',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_settlement',
    'db5iu14pf2t15n40lj40',
    'settlement',
    'db5iu14pf2t15n40lj2g',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu1kpf2t17kq31rd0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj2g', 'https://api.stawi.org/audit') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu1kpf2t17kq31rdg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj2g', 'https://api.stawi.org/profile') ON CONFLICT (id) DO NOTHING;


INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu1kpf2t17kq31reg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj2g', 'https://api.stawi.org/tenancy') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu1kpf2t17kq31rf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj2g', 'https://api.stawi.org/trustage') ON CONFLICT (id) DO NOTHING;
-- finance's ComplianceService.GetGenesisAccountPolicy; the genesis_policy_view grant follows once finance registers it.
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5kaq6u32d61l578m30', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj2g', 'https://api.stawi.org/stawi-finance') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES ('db5iu14pf2t15n40lj3g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj30', 1, 1, 0, 'pending', 0) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu1kpf2t17kq31rfg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj3g', 'service_audit', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rg0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31rfg', 'audit_create') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu1kpf2t17kq31rgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj3g', 'service_profile', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31rgg', 'account_resolve') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rhg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31rgg', 'profile_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu1kpf2t17kq31ri0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj3g', 'service_settlement', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'account_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'account_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'anchor_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rk0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'intent_submit') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rkg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'intent_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rl0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'observation_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rlg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'process_execute') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rm0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'room_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31ri0', 'room_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu1kpf2t17kq31rn0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj3g', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu1kpf2t17kq31rng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu1kpf2t17kq31rn0', 'event_ingest') ON CONFLICT (id) DO NOTHING;

-- TODO(stawi genesis policy): settlement will call finance's service-only
-- ComplianceService.GetGenesisAccountPolicy (permission genesis_policy_view in
-- namespace service_finance, stawilabs/stawi branch feat/cf-genesis-policy, not
-- yet on the release branch). Add that grant in a later migration once the
-- permission is in the finance manifest finance registers: a grant naming a
-- permission the registered manifest lacks fails this whole policy.
