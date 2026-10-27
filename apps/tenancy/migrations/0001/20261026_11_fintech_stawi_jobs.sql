-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech stawi: group cycles run on trustage (2026-10-26).
--
-- service-fintech stawi's group workflows never ran. Its periodic work is now
-- bounded jobs trustage calls: StawiJobRun (stawi_job_run, service accounts
-- only) sets groups up, closes due periods, reminds members and sweeps loan
-- offers. Stawi's setup job registers the schedules (it already holds
-- workflow_manage/workflow_view on service_trustage). The workflow callback
-- routes are gone, so its manifest dropped seven permissions; the stored
-- namespace is narrowed to match so the additive-only registration accepts it.

-- trustage → service_stawi
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfriuspf2t6d9r5297g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/stawi') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfriuspf2t6djgk4mkg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_stawi', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfriuspf2t6dsi4tcu0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfriuspf2t6djgk4mkg', 'stawi_job_run') ON CONFLICT (id) DO NOTHING;

UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp1f0';

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'trustage';

UPDATE service_namespaces
SET permissions = jsonb_set(permissions, '{values}', (permissions -> 'values') - ARRAY['stawi_group_view', 'stawi_group_manage', 'stawi_tenure_manage', 'stawi_period_manage', 'stawi_obligation_manage', 'stawi_loan_window_manage', 'stawi_loan_create']),
    role_bindings = (
        SELECT COALESCE(jsonb_object_agg(role, perms - ARRAY['stawi_group_view', 'stawi_group_manage', 'stawi_tenure_manage', 'stawi_period_manage', 'stawi_obligation_manage', 'stawi_loan_window_manage', 'stawi_loan_create']), '{}'::jsonb)
        FROM jsonb_each(role_bindings) AS rb(role, perms)
    ),
    generation = generation + 1,
    modified_at = CURRENT_TIMESTAMP
WHERE namespace = 'service_stawi'
  AND (permissions -> 'values') ?| ARRAY['stawi_group_view', 'stawi_group_manage', 'stawi_tenure_manage', 'stawi_period_manage', 'stawi_obligation_manage', 'stawi_loan_window_manage', 'stawi_loan_create'];
