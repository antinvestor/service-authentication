-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech limits: expiry schedules (2026-10-26).
--
-- service-fintech limits no longer reaps expired reservations and approvals
-- on an in-process timer: trustage fires their schedules, calling
-- LimitsAdminService.LimitsJobRun (limits_job_run, bound to no role). The
-- limits setup job registers the schedules with trustage (workflow_manage,
-- workflow_view on service_trustage).

-- service_limits → trustage
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfg9uspf2t1birgm9kg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd87bdkcpf2t58bn6vaeg', 'https://api.stawi.org/trustage') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfg9uspf2t1bsekodb0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmkpf2t39vdkpmb0', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfg9uspf2t1c5njths0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfg9uspf2t1bsekodb0', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfg9uspf2t1cfbbhpr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfg9uspf2t1bsekodb0', 'workflow_view') ON CONFLICT (id) DO NOTHING;

-- trustage → service_limits
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfg9uspf2t1coq6il30', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/limits') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfg9uspf2t1d26tdqr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_limits', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfg9uspf2t1db0bke8g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfg9uspf2t1d26tdqr0', 'limits_job_run') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('d94lkmkpf2t39vdkpmb0', 'd94lkmcpf2t39vdkp1f0');

-- Re-sync the Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-limits', 'trustage');
