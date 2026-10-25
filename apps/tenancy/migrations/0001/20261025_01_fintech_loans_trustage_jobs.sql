-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech loans: periodic jobs run by trustage (2026-10-25).
--
-- The loans service no longer runs timers in-process. Its setup job registers
-- scheduled workflows with trustage (client/workflows.SyncFromDir needs the
-- /trustage audience and workflow_view + workflow_manage on service_trustage),
-- and each schedule calls back, with trustage's own service token, into
-- LoanManagementService.LoanJobRun (permission loan_job_run on service_loans,
-- which needs the /loans audience on trustage's token).

-- service_loans → trustage
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbev6g4pf2t62071u7eg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnpvg', 'https://api.stawi.org/trustage') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbev6g4pf2t62071u7f0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp420', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbev6g4pf2t62071u7fg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbev6g4pf2t62071u7f0', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbev6g4pf2t62071u7g0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbev6g4pf2t62071u7f0', 'workflow_view') ON CONFLICT (id) DO NOTHING;

-- trustage → service_loans
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbev6g4pf2t62071u7gg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/loans') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbev6g4pf2t62071u7h0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_loans', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbev6g4pf2t62071u7hg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbev6g4pf2t62071u7h0', 'loan_job_run') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump both policies' generation so the reconciler
-- re-applies them. loan_job_run is registered by the loans setup job; a grant
-- naming it fails its policy until then, and registration re-queues it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('d94lkmcpf2t39vdkp420', 'd94lkmcpf2t39vdkp1f0');

-- Re-sync both Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-loans', 'trustage');
