-- Service account: operations_formstore (client operations-formstore,
-- d87bdkcpf2t58bn6vag0) uploads submission attachments to service-files.
-- service-trustage apps/formstore (v0.6.3) builds its files client on the
-- Frame HTTP client, which authenticates with this service account's own
-- client-credentials token, and calls only FilesService.UploadContent
-- (service/business/fileclient.go). It never reads, manages or deletes
-- content, so it gets the files audience and content_upload alone.
--
-- service-files authorises service callers by the Plane-2 tuple
-- service_file:<tenant>/<partition>#granted_content_upload@<sa profile>.

INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
)
SELECT 'dc5cf8bfukkv1p615240', NOW(), NOW(), 1, c.tenant_id, c.partition_id, c.id, 'https://api.stawi.org/files'
FROM public.clients c
WHERE c.client_id = 'operations-formstore'
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

-- The grant and permission are keyed by their natural uniques, so a grant
-- that already exists under another id is reused rather than aborting.
INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, version, tenant_id, partition_id, policy_id, namespace, scope
)
SELECT 'dc5cf8bfukkv1p61524g', NOW(), NOW(), 1, pol.tenant_id, pol.partition_id, pol.id, 'service_file', 'partition_tree'
FROM public.service_account_authorization_policies pol
JOIN public.service_accounts sa ON sa.id = pol.service_account_id
WHERE sa.client_id = 'operations-formstore'
  AND NOT EXISTS (
    SELECT 1 FROM public.service_account_authorization_grants g
    WHERE g.policy_id = pol.id AND g.namespace = 'service_file' AND g.scope = 'partition_tree'
  );

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, version, tenant_id, partition_id, grant_id, permission
)
SELECT 'dc5cf8bfukkv1p615250', NOW(), NOW(), 1, g.tenant_id, g.partition_id, g.id, 'content_upload'
FROM public.service_account_authorization_grants g
JOIN public.service_account_authorization_policies pol ON pol.id = g.policy_id
JOIN public.service_accounts sa ON sa.id = pol.service_account_id
WHERE sa.client_id = 'operations-formstore'
  AND g.namespace = 'service_file' AND g.scope = 'partition_tree'
  AND NOT EXISTS (
    SELECT 1 FROM public.service_account_authorization_permissions p
    WHERE p.grant_id = g.id AND p.permission = 'content_upload'
  );

-- New desired state: bump the policy generation so the reconciler re-applies it.
UPDATE public.service_account_authorization_policies pol
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error_code = '',
    last_error = NULL,
    modified_at = NOW()
FROM public.service_accounts sa
WHERE sa.id = pol.service_account_id
  AND sa.client_id = 'operations-formstore';

-- Re-sync the Hydra client so the files audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'operations-formstore';
