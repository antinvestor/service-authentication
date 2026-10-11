-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi authorization on the live platform (2026-10-11).
--
-- 1. Namespace ownership. Permission manifest registration only accepts a
--    manifest from the service account that owns the namespace: its name must
--    equal the namespace, or its client_id with hyphens as underscores
--    (serviceAccountOwnsNamespace). Chat's ChatService declares namespace
--    service_chat, but the chat service runs as the service_chat_drone account
--    (client service-chat-drone), which matches neither, so service_chat could
--    never be registered and no grant on it could reach Keto. Rename the
--    account to its namespace; client_id, keys and tokens are untouched (the
--    name is used only for namespace ownership). Same fix as
--    20260906_04_service_namespace_owners.sql.
--
-- 2. Finance posts display-only cards into Stawi rooms through chat's
--    SendEvent: the function-access interceptor requires event_send and the
--    service-card path then requires stawi_card_post, both in service_chat.
--    Finance already holds the chat audience (https://api.stawi.org/chat-drone).
--
-- 3. Settlement reads finance's service-only
--    ComplianceService.GetGenesisAccountPolicy: genesis_policy_view in
--    service_finance (resolves the TODO in 20261010_02_service_settlement.sql).
--    Settlement already holds the /stawi-finance audience.
--
-- 4. Settlement calls authentication's VerifyGenesisSessionProof
--    (auth_genesis_verify, granted in 20261011_02). The authentication app
--    accepts only its own resource audience, https://api.stawi.org/authentication
--    (cloud.deployment identity-authentication resource_path "/authentication"),
--    which settlement's client could not request until now.
--
-- A grant naming a permission the namespace has not registered yet fails its
-- policy until the owning service registers: RegisterPermissionManifest
-- re-queues every policy that grants the namespace, so the grants land as
-- soon as chat's and finance's setup jobs publish their manifests.

UPDATE public.service_accounts
SET name = 'service_chat', modified_at = NOW()
WHERE id = 'c2f4j7au6s7f91uqnpeg' AND name = 'service_chat_drone';

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5luv4pf2t0o1dkvss0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5itnspf2tft2pp30f0', 'service_chat', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5luv4pf2t0o1dkvssg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvss0', 'event_send') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5luv4pf2t0o1dkvst0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvss0', 'stawi_card_post') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5luv4pf2t0o1dkvstg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj3g', 'service_finance', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5luv4pf2t0o1dkvsu0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvstg', 'genesis_policy_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5mcvkpf2t12shm7gug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj2g', 'https://api.stawi.org/authentication') ON CONFLICT (client_ref, resource_audience) DO NOTHING;

-- New desired state → bump both policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('db5itnspf2tft2pp30f0', 'db5iu14pf2t15n40lj3g');

-- Re-sync the settlement Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'settlement';
