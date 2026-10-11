-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: trustage — Stawi finance and settlement audiences + grants.
-- Stawi's contracts run as Trustage workflows whose steps call back, with
-- trustage's own service token, into finance's process commands (permission
-- workflow_execute in namespace service_finance; bound to no role, held only
-- by Trustage, and finance also checks TRUSTAGE_PRINCIPAL) and settlement's
-- (RunDue, RefreshGasPrices: process_execute in namespace service_settlement).
-- The token needs the /stawi-finance and /stawi-settlement audiences.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu7cpf2t21sa27qdg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/stawi-finance') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu7cpf2t21sa27qe0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/stawi-settlement') ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu7cpf2t21sa27qeg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_finance', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu7cpf2t21sa27qf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu7cpf2t21sa27qeg', 'workflow_execute') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu7cpf2t21sa27qfg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_settlement', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu7cpf2t21sa27qg0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu7cpf2t21sa27qfg', 'process_execute') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp1f0';

-- Re-sync the Hydra client so the new audiences land in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'trustage';
