-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_chat_agent (platform-chat-agent Cloud Run app)
-- Owns permission namespace service_chat_agent; Hydra client_id service-chat-agent.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd9lemh4pf2t9nfnavkag',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_chat_agent',
    'service-chat-agent',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'd9lemh4pf2t9nfnavkbg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'd9lemh4pf2t9nfnavkbg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_chat_agent',
    'd9lemh4pf2t9nfnavkcg',
    'service-chat-agent',
    'd9lemh4pf2t9nfnavkag',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- Resource audiences this SA may request (tenancy auto-adds /tenancy when registering permissions).
INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('d9lemn4pf2t9a621dr00', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9lemh4pf2t9nfnavkag', 'https://api.stawi.org/chat-agent'),
  ('d9lemn4pf2t9a621dr0g', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9lemh4pf2t9nfnavkag', 'https://api.stawi.org/profile'),
  ('d9lemn4pf2t9a621dr10', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9lemh4pf2t9nfnavkag', 'https://api.stawi.org/tenancy'),
  ('d9lemn4pf2t9a621dr1g', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9lemh4pf2t9nfnavkag', 'https://api.stawi.org/notification')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

-- Authorization policy: owns service_chat_agent namespace.
INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
) VALUES (
  'd9lemh4pf2t9nfnavkc0', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'd9lemh4pf2t9nfnavkbg', 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
) VALUES (
  'd9lemn4pf2t9a621dr20', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'd9lemh4pf2t9nfnavkc0', 'service_chat_agent', 'partition_tree'
) ON CONFLICT (id) DO NOTHING;

-- Own-namespace permissions (must match chatagent.proto service_permissions).
INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
) VALUES
  ('d9lemn4pf2t9a621dr2g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9lemn4pf2t9a621dr20', 'chat_agent_view'),
  ('d9lemn4pf2t9a621dr30', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9lemn4pf2t9a621dr20', 'chat_agent_manage'),
  ('d9lemn4pf2t9a621dr3g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9lemn4pf2t9a621dr20', 'chat_agent_turn')
ON CONFLICT (id) DO NOTHING;

-- Force Hydra re-sync of this client.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-chat-agent';
