-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_commerce — create guest buyers' profiles.
-- A shop's public storefront takes orders from people who have not signed
-- in. Commerce finds the buyer's profile by the email or phone they enter
-- (profile_view, granted already) or creates a person profile for it, so
-- every buyer is a profile service profile.

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbb85ocpf2tf4p35bhqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dau0j24pf2t3vfe1ohrg', 'profile_create') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'daeltdcpf2t6p29e33g0';
