-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_calendar (platform-calendar Cloud Run)
-- Owns permission namespace service_calendar; Hydra client_id service-calendar.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd9ubvfcpf2tcpcf6c8jg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_calendar',
    'service-calendar',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'd9ubvfcpf2tcpcf6c8k0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'd9ubvfcpf2tcpcf6c8k0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_calendar',
    'd9ubvfcpf2tcpcf6c8kg',
    'service-calendar',
    'd9ubvfcpf2tcpcf6c8jg',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('d9ubvfcpf2tcpcf6c8lg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8jg', 'https://api.stawi.org/calendar'),
  ('d9ubvfcpf2tcpcf6c8m0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8jg', 'https://api.stawi.org/profile'),
  ('d9ubvfcpf2tcpcf6c8mg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8jg', 'https://api.stawi.org/tenancy')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
) VALUES (
  'd9ubvfcpf2tcpcf6c8l0', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'd9ubvfcpf2tcpcf6c8k0', 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
) VALUES (
  'd9ubvfcpf2tcpcf6c8n0', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'd9ubvfcpf2tcpcf6c8l0', 'service_calendar', 'partition_tree'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
) VALUES
  ('d9ubvfcpf2tcpcf6c8ng', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_resource_view'),
  ('d9ubvfcpf2tcpcf6c8o0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_resource_manage'),
  ('d9ubvfcpf2tcpcf6c8og', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_availability_manage'),
  ('d9ubvfcpf2tcpcf6c8p0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_slot_view'),
  ('d9ubvfcpf2tcpcf6c8pg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_booking_view'),
  ('d9ubvfcpf2tcpcf6c8q0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_booking_manage'),
  ('d9ubvfcpf2tcpcf6c8qg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8n0', 'calendar_sync_manage')
ON CONFLICT (id) DO NOTHING;

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-calendar';
