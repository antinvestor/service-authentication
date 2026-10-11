-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_finance
-- Stawi finance (stawilabs/stawi apps/finance, HelmRelease finance in namespace stawi). Owns permission namespace service_finance (every permission but workflow_execute, which only Trustage holds); Hydra client_id finance (colony uses the release name).

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'db5itnspf2tft2pp30e0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_finance',
    'finance',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'db5itnspf2tft2pp30eg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'db5itnspf2tft2pp30eg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_finance',
    'db5itnspf2tft2pp30fg',
    'finance',
    'db5itnspf2tft2pp30e0',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5ad0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/audit') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5adg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/chat-drone') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5ae0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/ledger') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5aeg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/notification') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5af0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/profile') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5afg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/stawi-settlement') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5ag0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/tenancy') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu0spf2t14odh5agg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30e0', 'https://api.stawi.org/trustage') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES ('db5itnspf2tft2pp30f0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30eg', 1, 1, 0, 'pending', 0) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5ah0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_audit', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ahg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ah0', 'audit_create') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5ai0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_finance', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5aig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'bucket_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5aj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'capability_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ajg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'capability_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ak0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'check_run') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5akg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'check_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5al0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'contribution_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5alg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'contribution_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5am0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'country_policy_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5amg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'country_policy_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5an0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'dispute_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ang', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'dispute_open') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ao0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'dispute_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5aog', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'distribution_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ap0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'distribution_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5apg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'escalation_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5aq0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'evidence_export') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5aqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'finance_operate') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ar0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'guarantee_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5arg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'intent_authorize') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5as0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'intent_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5asg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'ledger_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5at0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'limit_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5atg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'limit_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5au0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'loan_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5aug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'loan_submit') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5av0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'loan_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5avg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'member_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b00', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'period_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b0g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'plan_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b10', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'plan_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'policy_propose') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b20', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'policy_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b2g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'proposal_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b30', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'proposal_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b3g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'reconciliation_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b40', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'reconciliation_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b4g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'repayment_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b50', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'room_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b5g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'room_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b60', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'statement_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b6g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'transfer_request') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b70', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5ai0', 'vote_cast') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5b7g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_ledger', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b80', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'account_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b8g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'account_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b90', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'book_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5b9g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'book_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5ba0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'ledger_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bag', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'ledger_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bb0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'report_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bbg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'transaction_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bc0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5b7g', 'transaction_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5bcg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_notification', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bd0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bcg', 'notification_send') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bdg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bcg', 'template_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5be0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bcg', 'template_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5beg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_profile', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5beg', 'account_resolve') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bfg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5beg', 'profile_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5bg0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_settlement', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bg0', 'account_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu0spf2t14odh5bh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bhg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bh0', 'event_ingest') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5bi0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bh0', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu0spf2t14odh5big', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bh0', 'workflow_view') ON CONFLICT (id) DO NOTHING;
