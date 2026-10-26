-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech operations: the settle schedule (2026-10-26).
--
-- service-fintech operations settles individuals' payments that could not be
-- finished at once only when trustage fires its schedule, calling
-- OperationsService.OperationsJobRun (operations_job_run). The operations
-- setup job registers that schedule with trustage (workflow_manage,
-- workflow_view on service_trustage).

-- service_operations → trustage
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbffi8kpf2t5nupkb8m0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq7g', 'https://api.stawi.org/trustage') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbffi8kpf2t5o80eflug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp8i0', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbffi8spf2t5oh3oceng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbffi8kpf2t5o80eflug', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbffi8spf2t5oq8rfprg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbffi8kpf2t5o80eflug', 'workflow_view') ON CONFLICT (id) DO NOTHING;

-- trustage → service_operations
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbffi8spf2t5p3hqo4jg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/operations') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbffi8spf2t5pceoscp0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_operations', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbffi8spf2t5pra4ner0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbffi8spf2t5pceoscp0', 'operations_job_run') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('d94lkmcpf2t39vdkp8i0', 'd94lkmcpf2t39vdkp1f0');

-- Re-sync the Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-operations', 'trustage');
