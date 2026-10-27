-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech identity: KYC documents (2026-10-26).
--
-- service-fintech identity keeps clients' KYC photos and documents in
-- service-files. It uploads them privately as itself (content_upload), so it
-- is their only owner, and hands a reviewer a short-lived signed download
-- link after checking they may see the client (content_view).

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfldecpf2t9sfi4kpmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnptg', 'https://api.stawi.org/files') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfldecpf2t9st1hd6tg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp3eg', 'service_file', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfldecpf2t9t68kf1ng', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfldecpf2t9st1hd6tg', 'content_upload') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbflddkpf2t9riqen5rg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfldecpf2t9st1hd6tg', 'content_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy's generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp3eg';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-identity';
