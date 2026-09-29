-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_payment_flutterwave
-- Flutterwave payment integration (service-payment apps/integrations/flutterwave,
-- Cloud Run payment-flutterwave); Hydra client_id service-payment-flutterwave.
--
-- Flutterwave was deployed without a tenancy SA seed, so the Hydra client, SA
-- and ReBAC grants were incomplete: charges succeeded at the provider but the
-- StatusUpdate write-back failed with permission_denied on
-- payment_status_update and checkout hung on "Confirm payment".
--
-- Mirrors the service-payment-stripe / service-payment-pawapay integration SA
-- contract: recipients notification/payment/profile/tenancy and partition_tree
-- grants on service_notification, service_payment, service_profile and
-- service_tenancy with the same permission sets.
--
-- Bot profile d9flwbotprof00000001 already exists in the profile service (bot type) and
-- already holds the operationally materialised Keto grants; it is kept as-is.
--
-- Rows are resolved by client_id and inserted with ON CONFLICT DO NOTHING so the
-- migration is also safe where the client/SA was created by hand before this
-- seed existed (unique client_id). The repair statements only touch such
-- legacy rows and are no-ops on a greenfield database.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'datmso4pf2t98sc6rov0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_payment_flutterwave',
    'service-payment-flutterwave',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'datmso4pf2t98sc6rovg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
)
SELECT 'datmso4pf2t98sc6rovg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'service_payment_flutterwave', 'd9flwbotprof00000001',
       c.client_id, c.id, 'internal', '{}'
FROM clients c
WHERE c.client_id = 'service-payment-flutterwave'
ON CONFLICT DO NOTHING;

-- Legacy repair: bind a hand-created SA row to the bot profile and client row.
UPDATE service_accounts sa
SET name = 'service_payment_flutterwave',
    profile_id = 'd9flwbotprof00000001',
    client_ref = c.id,
    type = 'internal',
    modified_at = NOW()
FROM clients c
WHERE c.client_id = 'service-payment-flutterwave'
  AND sa.client_id = c.client_id
  AND (sa.name IS DISTINCT FROM 'service_payment_flutterwave'
       OR sa.profile_id IS DISTINCT FROM 'd9flwbotprof00000001'
       OR sa.client_ref IS DISTINCT FROM c.id
       OR sa.type IS DISTINCT FROM 'internal');

-- Legacy repair: point a hand-created client row at its SA; the Hydra client
-- metadata (service_account_id, profile_id) is rebuilt from it on client sync.
UPDATE clients c
SET service_account_id = sa.id,
    token_endpoint_auth_method = 'private_key_jwt',
    modified_at = NOW()
FROM service_accounts sa
WHERE c.client_id = 'service-payment-flutterwave'
  AND sa.client_id = c.client_id
  AND (c.service_account_id IS DISTINCT FROM sa.id
       OR c.token_endpoint_auth_method IS DISTINCT FROM 'private_key_jwt');

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience)
SELECT v.id, c.tenant_id, c.partition_id, c.id, v.aud
FROM clients c
CROSS JOIN (VALUES
    ('datmso4pf2t98sc6rp0g', 'https://api.stawi.org/notification'),
    ('datmso4pf2t98sc6rp10', 'https://api.stawi.org/payment'),
    ('datmso4pf2t98sc6rp1g', 'https://api.stawi.org/profile'),
    ('datmso4pf2t98sc6rp20', 'https://api.stawi.org/tenancy')
) AS v(id, aud)
WHERE c.client_id = 'service-payment-flutterwave'
ON CONFLICT DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count)
SELECT 'datmso4pf2t98sc6rp00', sa.tenant_id, sa.partition_id, sa.id, 1, 1, 0, 'pending', 0
FROM service_accounts sa
WHERE sa.client_id = 'service-payment-flutterwave'
ON CONFLICT DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope)
SELECT v.id, p.tenant_id, p.partition_id, p.id, v.ns, 'partition_tree'
FROM service_account_authorization_policies p
JOIN service_accounts sa ON sa.id = p.service_account_id
CROSS JOIN (VALUES
    ('datmso4pf2t98sc6rp2g', 'service_notification'),
    ('datmso4pf2t98sc6rp30', 'service_payment'),
    ('datmso4pf2t98sc6rp3g', 'service_profile'),
    ('datmso4pf2t98sc6rp40', 'service_tenancy')
) AS v(id, ns)
WHERE sa.client_id = 'service-payment-flutterwave'
ON CONFLICT DO NOTHING;

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission)
SELECT v.id, g.tenant_id, g.partition_id, g.id, v.perm
FROM service_account_authorization_grants g
JOIN service_account_authorization_policies p ON p.id = g.policy_id
JOIN service_accounts sa ON sa.id = p.service_account_id
JOIN (VALUES
    ('datmso4pf2t98sc6rp4g', 'service_notification', 'notification_release'),
    ('datmso4pf2t98sc6rp50', 'service_notification', 'notification_search'),
    ('datmso4pf2t98sc6rp5g', 'service_notification', 'notification_send'),
    ('datmso4pf2t98sc6rp60', 'service_notification', 'notification_status_update'),
    ('datmso4pf2t98sc6rp6g', 'service_notification', 'notification_status_view'),
    ('datmso4pf2t98sc6rp70', 'service_notification', 'template_manage'),
    ('datmso4pf2t98sc6rp7g', 'service_notification', 'template_view'),
    ('datmso4pf2t98sc6rp80', 'service_payment', 'payment_link_create'),
    ('datmso4pf2t98sc6rp8g', 'service_payment', 'payment_receive'),
    ('datmso4pf2t98sc6rp90', 'service_payment', 'payment_release'),
    ('datmso4pf2t98sc6rp9g', 'service_payment', 'payment_search'),
    ('datmso4pf2t98sc6rpa0', 'service_payment', 'payment_send'),
    ('datmso4pf2t98sc6rpag', 'service_payment', 'payment_status_update'),
    ('datmso4pf2t98sc6rpb0', 'service_payment', 'payment_status_view'),
    ('datmso4pf2t98sc6rpbg', 'service_payment', 'prompt_initiate'),
    ('datmso4pf2t98sc6rpc0', 'service_payment', 'reconcile'),
    ('datmso4pf2t98sc6rpcg', 'service_profile', 'address_manage'),
    ('datmso4pf2t98sc6rpd0', 'service_profile', 'contact_manage'),
    ('datmso4pf2t98sc6rpdg', 'service_profile', 'profile_create'),
    ('datmso4pf2t98sc6rpe0', 'service_profile', 'profile_merge'),
    ('datmso4pf2t98sc6rpeg', 'service_profile', 'profile_update'),
    ('datmso4pf2t98sc6rpf0', 'service_profile', 'profile_view'),
    ('datmso4pf2t98sc6rpfg', 'service_profile', 'relationship_manage'),
    ('datmso4pf2t98sc6rpg0', 'service_profile', 'relationship_view'),
    ('datmso4pf2t98sc6rpgg', 'service_profile', 'roster_manage'),
    ('datmso4pf2t98sc6rph0', 'service_profile', 'roster_view'),
    ('datmso4pf2t98sc6rphg', 'service_tenancy', 'access_manage'),
    ('datmso4pf2t98sc6rpi0', 'service_tenancy', 'access_view'),
    ('datmso4pf2t98sc6rpig', 'service_tenancy', 'client_manage'),
    ('datmso4pf2t98sc6rpj0', 'service_tenancy', 'client_view'),
    ('datmso4pf2t98sc6rpjg', 'service_tenancy', 'page_manage'),
    ('datmso4pf2t98sc6rpk0', 'service_tenancy', 'page_view'),
    ('datmso4pf2t98sc6rpkg', 'service_tenancy', 'partition_manage'),
    ('datmso4pf2t98sc6rpl0', 'service_tenancy', 'partition_view'),
    ('datmso4pf2t98sc6rplg', 'service_tenancy', 'permission_grant'),
    ('datmso4pf2t98sc6rpm0', 'service_tenancy', 'role_manage'),
    ('datmso4pf2t98sc6rpmg', 'service_tenancy', 'service_account_manage'),
    ('datmso4pf2t98sc6rpn0', 'service_tenancy', 'service_account_view'),
    ('datmso4pf2t98sc6rpng', 'service_tenancy', 'tenant_manage'),
    ('datmso4pf2t98sc6rpo0', 'service_tenancy', 'tenant_view')
) AS v(id, ns, perm) ON v.ns = g.namespace
WHERE sa.client_id = 'service-payment-flutterwave'
  AND g.scope = 'partition_tree'
ON CONFLICT DO NOTHING;

-- Legacy repair: a policy that was already applied must be re-materialised so
-- the added permissions reach Keto. A freshly inserted policy is already pending.
UPDATE service_account_authorization_policies p
SET generation = p.generation + 1,
    status = 'pending',
    modified_at = NOW()
FROM service_accounts sa
WHERE p.service_account_id = sa.id
  AND sa.client_id = 'service-payment-flutterwave'
  AND p.applied_generation = p.generation;
