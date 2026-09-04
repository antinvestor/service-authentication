-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_imports — files audience + grants.
-- The imports API stores product images in service-files (public
-- visibility) on behalf of admins and manages them afterwards, which needs
-- a token with the /files audience and content_* in namespace service_file.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dadbslspf2t8u24o8r1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uap0', 'https://api.stawi.org/files') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dadbslspf2t8u24o8r20', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uaqg', 'service_file', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dadbslspf2t8u24o8r2g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dadbslspf2t8u24o8r20', 'content_upload') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dadbslspf2t8u24o8r30', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dadbslspf2t8u24o8r20', 'content_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dadbslspf2t8u24o8r3g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dadbslspf2t8u24o8r20', 'content_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dadbslspf2t8u24o8r40', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dadbslspf2t8u24o8r20', 'content_delete') ON CONFLICT (id) DO NOTHING;

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
