-- Copyright 2023-2026 Ant Investor Ltd
--
-- Service account: service_payment_flutterwave
-- Cloud Run: payment-flutterwave (client_id service-payment-flutterwave)
--
-- Flutterwave was deployed as a payment integration without a tenancy SA seed.
-- That left Hydra client/authz/Keto grants incomplete, so StatusUpdate after a
-- successful charge failed with permission_denied on payment_status_update and
-- checkout hung on "Confirm payment".
--
-- Mirrors the stripe payment-integration SA contract (audiences + partition_tree
-- grants on service_payment / service_profile / service_tenancy /
-- service_notification).
--
-- Bot profile d9flwbotprof00000001 already exists in profile service (type bot).
-- Hydra client service-payment-flutterwave must set metadata.profile_id to that
-- profile and metadata.service_account_id to the SA row below.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd9r3e64pf2t8o8sm3qtg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_flutterwave',
    'service-payment-flutterwave',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'd9r3e64pf2t8o8sm3qu0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

UPDATE clients
SET name = 'sa-service_payment_flutterwave',
    service_account_id = 'd9r3e64pf2t8o8sm3qu0',
    token_endpoint_auth_method = 'private_key_jwt',
    modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-payment-flutterwave';

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'd9r3e64pf2t8o8sm3qu0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_payment_flutterwave',
    'd9flwbotprof00000001',
    'service-payment-flutterwave',
    'd9r3e64pf2t8o8sm3qtg',
    'internal',
    '{}'
) ON CONFLICT (id) DO UPDATE SET
    profile_id = EXCLUDED.profile_id,
    client_id = EXCLUDED.client_id,
    client_ref = EXCLUDED.client_ref,
    type = EXCLUDED.type,
    modified_at = NOW();

-- If a legacy row exists under the same human client_id with a different id,
-- retarget it to the bot profile / client ref (unique client_id prevents a
-- second row).
UPDATE service_accounts
SET profile_id = 'd9flwbotprof00000001',
    client_ref = (SELECT id FROM clients WHERE client_id = 'service-payment-flutterwave' LIMIT 1),
    name = 'service_payment_flutterwave',
    type = 'internal',
    modified_at = NOW()
WHERE client_id = 'service-payment-flutterwave';

-- Resource audiences this SA may request (matches payment-flutterwave Cloud Run
-- OAUTH2_REQUESTED_AUDIENCES + payment integration peers).
INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
)
SELECT
  v.id, NOW(), NOW(), 1, c.tenant_id, c.partition_id, c.id, v.aud
FROM public.clients c
CROSS JOIN (
  VALUES
    ('d9r3e64pf2t8o8sm3qv0', 'https://api.stawi.org/notification'),
    ('d9r3e64pf2t8o8sm3qvg', 'https://api.stawi.org/payment'),
    ('d9r3e64pf2t8o8sm3r00', 'https://api.stawi.org/profile'),
    ('d9r3e64pf2t8o8sm3r0g', 'https://api.stawi.org/tenancy')
) AS v(id, aud)
WHERE c.client_id = 'service-payment-flutterwave'
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

-- Authorization policy (pending → materialised by setup ReconcilePending / sync).
INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
)
SELECT
  'd9r3e64pf2t8o8sm3qug', NOW(), NOW(), '', '', 1,
  sa.tenant_id, sa.partition_id, '', NULL,
  sa.id, 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
FROM public.service_accounts sa
WHERE sa.client_id = 'service-payment-flutterwave'
ON CONFLICT (id) DO NOTHING;

-- Ensure a policy exists even if the fixed policy id collided empty.
INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
)
SELECT
  'd9r3e64pf2t8o8sm3qug', NOW(), NOW(), '', '', 1,
  sa.tenant_id, sa.partition_id, '', NULL,
  sa.id, 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
FROM public.service_accounts sa
WHERE sa.client_id = 'service-payment-flutterwave'
  AND NOT EXISTS (
    SELECT 1 FROM public.service_account_authorization_policies p
    WHERE p.service_account_id = sa.id
  );

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
)
SELECT
  v.id, NOW(), NOW(), '', '', 1,
  p.tenant_id, p.partition_id, '', NULL,
  p.id, v.ns, 'partition_tree'
FROM public.service_account_authorization_policies p
JOIN public.service_accounts sa ON sa.id = p.service_account_id
CROSS JOIN (
  VALUES
    ('d9r3e64pf2t8o8sm3r10', 'service_notification'),
    ('d9r3e64pf2t8o8sm3r1g', 'service_payment'),
    ('d9r3e64pf2t8o8sm3r20', 'service_profile'),
    ('d9r3e64pf2t8o8sm3r2g', 'service_tenancy')
) AS v(id, ns)
WHERE sa.client_id = 'service-payment-flutterwave'
ON CONFLICT (id) DO NOTHING;

-- service_notification permissions (parity with payment-stripe integration SA)
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
    ('d9r3e64pf2t8o8sm3r30', 'notification_release'),
    ('d9r3e64pf2t8o8sm3r3g', 'notification_search'),
    ('d9r3e64pf2t8o8sm3r40', 'notification_send'),
    ('d9r3e64pf2t8o8sm3r4g', 'notification_status_update'),
    ('d9r3e64pf2t8o8sm3r50', 'notification_status_view'),
    ('d9r3e64pf2t8o8sm3r5g', 'template_manage'),
    ('d9r3e64pf2t8o8sm3r60', 'template_view')
) AS v(id, perm)
WHERE g.id = 'd9r3e64pf2t8o8sm3r10'
ON CONFLICT (id) DO NOTHING;

-- service_payment permissions — payment_status_update is required for charge
-- result write-back that unblocks pay.stawi.org confirm polling.
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
    ('d9r3e64pf2t8o8sm3r6g', 'payment_link_create'),
    ('d9r3e64pf2t8o8sm3r70', 'payment_receive'),
    ('d9r3e64pf2t8o8sm3r7g', 'payment_release'),
    ('d9r3e64pf2t8o8sm3r80', 'payment_search'),
    ('d9r3e64pf2t8o8sm3r8g', 'payment_send'),
    ('d9r3e64pf2t8o8sm3r90', 'payment_status_update'),
    ('d9r3e64pf2t8o8sm3r9g', 'payment_status_view'),
    ('d9r3e64pf2t8o8sm3ra0', 'prompt_initiate'),
    ('d9r3e64pf2t8o8sm3rag', 'reconcile')
) AS v(id, perm)
WHERE g.id = 'd9r3e64pf2t8o8sm3r1g'
ON CONFLICT (id) DO NOTHING;

-- service_profile
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
    ('d9r3e64pf2t8o8sm3rb0', 'address_manage'),
    ('d9r3e64pf2t8o8sm3rbg', 'contact_manage'),
    ('d9r3e64pf2t8o8sm3rc0', 'profile_create'),
    ('d9r3e64pf2t8o8sm3rcg', 'profile_merge'),
    ('d9r3e64pf2t8o8sm3rd0', 'profile_update'),
    ('d9r3e64pf2t8o8sm3rdg', 'profile_view'),
    ('d9r3e64pf2t8o8sm3re0', 'relationship_manage'),
    ('d9r3e64pf2t8o8sm3reg', 'relationship_view'),
    ('d9r3e64pf2t8o8sm3rf0', 'roster_manage'),
    ('d9r3e64pf2t8o8sm3rfg', 'roster_view')
) AS v(id, perm)
WHERE g.id = 'd9r3e64pf2t8o8sm3r20'
ON CONFLICT (id) DO NOTHING;

-- service_tenancy
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
    ('d9r3e64pf2t8o8sm3rg0', 'access_manage'),
    ('d9r3e64pf2t8o8sm3rgg', 'access_view'),
    ('d9r3e64pf2t8o8sm3rh0', 'client_manage'),
    ('d9r3e64pf2t8o8sm3rhg', 'client_view'),
    ('d9r3e64pf2t8o8sm3ri0', 'page_manage'),
    ('d9r3e64pf2t8o8sm3rig', 'page_view'),
    ('d9r3e64pf2t8o8sm3rj0', 'partition_manage'),
    ('d9r3e64pf2t8o8sm3rjg', 'partition_view'),
    ('d9r3e64pf2t8o8sm3rk0', 'permission_grant'),
    ('d9r3e64pf2t8o8sm3rkg', 'role_manage'),
    ('d9r3e64pf2t8o8sm3rl0', 'service_account_manage'),
    ('d9r3e64pf2t8o8sm3rlg', 'service_account_view'),
    ('d9r3e64pf2t8o8sm3rm0', 'tenant_manage'),
    ('d9r3ek4pf2t8vfqg5pn0', 'tenant_view')
) AS v(id, perm)
WHERE g.id = 'd9r3e64pf2t8o8sm3r2g'
ON CONFLICT (id) DO NOTHING;

-- Bump policy generation so setup/reconcile re-materialises Keto grants.
UPDATE public.service_account_authorization_policies p
SET generation = GREATEST(generation, 1) + 1,
    status = 'pending',
    applied_generation = 0,
    modified_at = NOW(),
    last_error = '',
    last_error_code = ''
FROM public.service_accounts sa
WHERE p.service_account_id = sa.id
  AND sa.client_id = 'service-payment-flutterwave';

-- Force Hydra re-sync of this client (metadata profile_id/SA id).
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-payment-flutterwave';
