-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_procurement — manufacturing audience + plan grant.
-- Purchase order suggestions read a production plan and its material
-- shortages from manufacturing with procurement's own token, so it needs the
-- /manufacturing audience and plan_view in service_manufacturing.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbas5dcpf2t4oekfdkgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e3410', 'https://api.stawi.org/manufacturing') ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbas5dcpf2t4oekfdkh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e342g', 'service_manufacturing', 'partition_tree') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbas5dcpf2t4oekfdkhg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbas5dcpf2t4oekfdkh0', 'plan_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'daeltdcpf2t6p29e342g';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-procurement';
