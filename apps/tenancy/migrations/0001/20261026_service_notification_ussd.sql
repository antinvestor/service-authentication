-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_notification_ussd
-- USSD engine of service-notification: resolves callers through profile and hands completed sessions to notification.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'dbfc76cpf2t8llgjlgp0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_ussd',
    'service-notification-ussd',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'dbfc76cpf2t8llgjlgq0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'dbfc76cpf2t8llgjlgq0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification_ussd',
    'dbfc74kpf2t8jtt127bg',
    'service-notification-ussd',
    'dbfc76cpf2t8llgjlgp0',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfc76kpf2t8meirgt70', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgp0', 'https://api.stawi.org/notification') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfc76kpf2t8meirgt7g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgp0', 'https://api.stawi.org/profile') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES ('dbfc76cpf2t8llgjlgqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgq0', 1, 1, 0, 'pending', 0) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfc76kpf2t8meirgt80', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgqg', 'service_notification', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfc76kpf2t8meirgt8g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76kpf2t8meirgt80', 'notification_send') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfc76kpf2t8meirgt90', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgqg', 'service_profile', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfc76kpf2t8meirgt9g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76kpf2t8meirgt90', 'profile_view') ON CONFLICT (id) DO NOTHING;

-- When a borrower opens Seed's menu the engine asks Seed for their current
-- state (seed_ussd_state on service_seed) before the first screen.
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfctccpf2t3vvghmsb0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgp0', 'https://api.stawi.org/seed') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfctccpf2t3vvghmsbg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfc76cpf2t8llgjlgqg', 'service_seed', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfctccpf2t3vvghmsc0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfctccpf2t3vvghmsbg', 'seed_ussd_state') ON CONFLICT (id) DO NOTHING;

-- service_seed: Seed runs the borrower USSD menu. It registers its menu tree
-- and pushes each borrower's state through the USSD management API, and it
-- sends the one-time code that guards a borrower setting their USSD PIN
-- (CreateContactVerification needs contact_manage). Seed never records a
-- repayment: borrowers pay from their own contact and the payment rail
-- records it, so its repayment_manage grant goes.
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfc91cpf2tb4t2sfa1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq9g', 'https://api.stawi.org/ussd') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfc91cpf2tb4t2sfa20', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4eto0', 'contact_manage') ON CONFLICT (id) DO NOTHING;
DELETE FROM service_account_authorization_permissions p
USING service_account_authorization_grants g
WHERE p.grant_id = g.id
  AND g.policy_id = 'd94lkmcpf2t39vdkpa4g'
  AND g.namespace = 'service_loans'
  AND p.permission = 'repayment_manage';

-- Seed texts borrowers the outcome of what they asked for on USSD.
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfcjespf2tf7ot651n0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq9g', 'https://api.stawi.org/notification') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfcjespf2tf7ot651ng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkpa4g', 'service_notification', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfcjespf2tf7ot651o0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfcjespf2tf7ot651ng', 'notification_send') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('d94lkmcpf2t39vdkpa4g');

-- Re-sync the Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-seed');
