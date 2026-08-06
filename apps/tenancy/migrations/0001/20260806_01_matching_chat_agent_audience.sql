-- Copyright 2023-2026 Ant Investor Ltd
-- Allow opportunities-matching to call platform chat-agent (S2S).
-- Without oauth_client_recipients for https://api.stawi.org/chat-agent, Hydra
-- rejects client_credentials with:
--   Requested audience 'https://api.stawi.org/chat-agent' has not been whitelisted
-- Also grant service_chat_agent functional permissions so Turn/CreateSession
-- pass ReBAC after the token is issued. Add checkout audience already
-- requested by matching env.

-- Resolve opportunities-matching client + policy via stable client_id (not hardcoded seed xids).
-- New row xids for this migration (registered in IDS.md):
--   d9mchat1matchaud0001, d9mchat1matchaud0002 (recipients)
--   d9mchat1matchgrant001 (grant)
--   d9mchat1matchperm0001..0003 (permissions)

INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
)
SELECT
  v.id, NOW(), NOW(), 1, c.tenant_id, c.partition_id, c.id, v.aud
FROM public.clients c
CROSS JOIN (
  VALUES
    ('d9mchat1matchaud0001', 'https://api.stawi.org/chat-agent'),
    ('d9mchat1matchaud0002', 'https://api.stawi.org/checkout')
) AS v(id, aud)
WHERE c.client_id = 'opportunities-matching'
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
)
SELECT
  'd9mchat1matchgrant001', NOW(), NOW(), '', '', 1,
  p.tenant_id, p.partition_id, '', NULL,
  p.id, 'service_chat_agent', 'partition_tree'
FROM public.service_account_authorization_policies p
JOIN public.service_accounts sa ON sa.id = p.service_account_id
WHERE sa.client_id = 'opportunities-matching'
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
)
SELECT
  v.id, NOW(), NOW(), '', '', 1,
  g.tenant_id, g.partition_id, '', NULL,
  g.id, v.perm
FROM public.service_account_authorization_grants g
CROSS JOIN (
  VALUES
    ('d9mchat1matchperm0001', 'chat_agent_view'),
    ('d9mchat1matchperm0002', 'chat_agent_manage'),
    ('d9mchat1matchperm0003', 'chat_agent_turn')
) AS v(id, perm)
WHERE g.id = 'd9mchat1matchgrant001'
ON CONFLICT (id) DO NOTHING;

-- Bump policy generation so setup/reconcile re-materialises Keto grants.
UPDATE public.service_account_authorization_policies p
SET generation = generation + 1,
    status = 'pending',
    modified_at = NOW(),
    last_error = '',
    last_error_code = ''
FROM public.service_accounts sa
WHERE p.service_account_id = sa.id
  AND sa.client_id = 'opportunities-matching';

-- Force Hydra re-sync of opportunities-matching client audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'opportunities-matching';
