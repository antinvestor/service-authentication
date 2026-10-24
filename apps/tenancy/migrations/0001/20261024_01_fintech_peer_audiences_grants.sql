-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech service accounts: audiences and grants for service-fintech v1.96.3x
-- (connect v2, transaction limits on by default; 2026-10-24).
--
-- Every finance service now reserves against the limits service before it
-- moves money (limits_use in service_limits), the limits service resolves
-- borrowers through the field service and investors through identity, and
-- operations records allocated group repayments with loans. The setup Jobs
-- of v1.96.30/31 failed to mint their tokens because the clients were not
-- whitelisted for audiences their stacks request ("Requested audience ... has
-- not been whitelisted by the OAuth 2.0 Client").
--
-- Recipients add the audiences; grants add the permissions the callee checks.
-- A grant naming a permission its namespace has not registered yet fails its
-- policy until the owning service's setup job registers it; registration
-- re-queues every policy that grants the namespace.


-- service_loans
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4et6g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnpvg', 'https://api.stawi.org/limits') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4et70', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp420', 'service_limits', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4et7g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4et70', 'limits_use') ON CONFLICT (id) DO NOTHING;

-- service_limits
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4et80', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd87bdkcpf2t58bn6vaeg', 'https://api.stawi.org/audit') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4et8g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd87bdkcpf2t58bn6vaeg', 'https://api.stawi.org/identity') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4et90', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmkpf2t39vdkpmb0', 'service_field', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4et9g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4et90', 'client_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4eta0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmkpf2t39vdkpmb0', 'service_identity', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etag', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4eta0', 'investor_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etb0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmkpf2t39vdkpmb0', 'service_audit', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etbg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etb0', 'audit_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etc0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etb0', 'audit_verify') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etcg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etb0', 'audit_view') ON CONFLICT (id) DO NOTHING;

-- service_operations
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etd0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq7g', 'https://api.stawi.org/limits') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etdg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq7g', 'https://api.stawi.org/loans') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4ete0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp8i0', 'service_limits', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4eteg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4ete0', 'limits_use') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp8i0', 'service_loans', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etfg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etf0', 'repayment_manage') ON CONFLICT (id) DO NOTHING;

-- service_savings
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etg0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq5g', 'https://api.stawi.org/limits') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp7f0', 'service_limits', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4eth0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etgg', 'limits_use') ON CONFLICT (id) DO NOTHING;

-- service_funding
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4ethg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq3g', 'https://api.stawi.org/limits') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4eti0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq3g', 'https://api.stawi.org/savings') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp5f0', 'service_limits', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etig', 'limits_use') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp5f0', 'service_savings', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etk0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etjg', 'savings_account_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etkg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etjg', 'savings_balance_view') ON CONFLICT (id) DO NOTHING;

-- service_seed
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etl0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq9g', 'https://api.stawi.org/profile') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etlg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq9g', 'https://api.stawi.org/audit') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etm0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkpa4g', 'service_audit', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etm0', 'audit_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etn0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etm0', 'audit_verify') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etm0', 'audit_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4eto0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkpa4g', 'service_profile', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etog', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4eto0', 'profile_view') ON CONFLICT (id) DO NOTHING;

-- service_stawi
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etp0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnqbg', 'https://api.stawi.org/limits') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbe6k5g1j4o4jru4etpg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnqbg', 'https://api.stawi.org/audit') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etq0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkpbk0', 'service_limits', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etq0', 'limits_use') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbe6k5g1j4o4jru4etr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkpbk0', 'service_audit', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etrg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etr0', 'audit_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4ets0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etr0', 'audit_verify') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbe6k5g1j4o4jru4etsg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etr0', 'audit_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('d94lkmcpf2t39vdkp420', 'd94lkmkpf2t39vdkpmb0', 'd94lkmcpf2t39vdkp8i0', 'd94lkmcpf2t39vdkp7f0', 'd94lkmcpf2t39vdkp5f0', 'd94lkmcpf2t39vdkpa4g', 'd94lkmcpf2t39vdkpbk0');

-- Re-sync the Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-loans', 'service-limits', 'service-operations', 'service-savings', 'service-funding', 'service-seed', 'service-stawi');
