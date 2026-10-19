-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_commerce — currency-source audiences + grants.
-- Commerce defaults a new shop's currency to the creating user's: their
-- "currency" setting (settings service), else their device locale (device
-- service), else their profile address country (profile service). It reads
-- those with its own token, so it needs the /settings and /devices audiences
-- (it already requests /profile) and view grants in each namespace.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dau0j24pf2t3vfe1ohpg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/settings') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dau0j24pf2t3vfe1ohq0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/devices') ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dau0j24pf2t3vfe1ohqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33g0', 'service_setting', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dau0j24pf2t3vfe1ohr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33g0', 'service_device', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dau0j24pf2t3vfe1ohrg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33g0', 'service_profile', 'partition_tree') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dau0j24pf2t3vfe1ohs0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dau0j24pf2t3vfe1ohqg', 'setting_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dau0j24pf2t3vfe1ohsg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dau0j24pf2t3vfe1ohr0', 'device_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dau0j24pf2t3vfe1oht0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dau0j24pf2t3vfe1ohrg', 'profile_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'daeltdcpf2t6p29e33g0';

-- Re-sync the Hydra client so the new audiences land in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-commerce';
