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
) VALUES
  ('dc5cf8bfukkv1p615240', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd87bdkcpf2t58bn6vag0', 'https://api.stawi.org/files')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, version, tenant_id, partition_id, policy_id, namespace, scope
) VALUES
  ('dc5cf8bfukkv1p61524g', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmkpf2t39vdkpn2g', 'service_file', 'partition_tree')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, version, tenant_id, partition_id, grant_id, permission
) VALUES
  ('dc5cf8bfukkv1p615250', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dc5cf8bfukkv1p61524g', 'content_upload')
ON CONFLICT (id) DO NOTHING;

-- New desired state: bump the policy generation so the reconciler re-applies it.
UPDATE public.service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmkpf2t39vdkpn2g';

-- Re-sync the Hydra client so the files audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'operations-formstore';
