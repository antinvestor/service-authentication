-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_imports — trustage audience + grants (Phase 2 lifecycle sweeps).
-- The imports setup job syncs cron workflow definitions into trustage
-- (client/workflows.SyncFromDir), which needs a token with the /trustage
-- audience and workflow_view + workflow_manage in namespace service_trustage.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daan2nkpf2t03l5g386g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uap0', 'https://api.stawi.org/trustage') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daan2nkpf2t03l5g3870', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uaqg', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daan2nkpf2t03l5g387g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daan2nkpf2t03l5g3870', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daan2nkpf2t03l5g3880', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daan2nkpf2t03l5g3870', 'workflow_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'daaltq4pf2tb6me3uaqg';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'imports';
