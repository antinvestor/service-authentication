-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_imports — identity audience + read grants (Admin Settings → Identity & Access).
-- The imports API resolves a caller's workforce record and team memberships from the identity
-- service to derive access bundles / TEAM scope, which needs a token with the /identity audience
-- and workforce_member_view + team_view + team_membership_view in namespace service_identity.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daaour1f39n0ifkgrv31', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uap0', 'https://api.stawi.org/identity') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daaomolp4gr0qukc6sbi', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uaqg', 'service_identity', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaod4dssiicthalhbah', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaomolp4gr0qukc6sbi', 'workforce_member_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daaolf7gln59nje4cd1b', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaomolp4gr0qukc6sbi', 'team_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daao7mg15br87bq1h5ia', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaomolp4gr0qukc6sbi', 'team_membership_view') ON CONFLICT (id) DO NOTHING;

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
