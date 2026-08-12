-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_ats (opportunities-ats Cloud Run)
-- Owns permission namespace service_ats; Hydra client_id service-ats.
-- Peer: service_calendar (platform-calendar) for interview scheduling.
-- Also adds /ats audience + /ats/auth/callback redirect on the Opportunities SPA.

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'd9ubvfcpf2tcpcf6c8r0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_ats',
    'service-ats',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'd9ubvfcpf2tcpcf6c8rg',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'd9ubvfcpf2tcpcf6c8rg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_ats',
    'd9ubvfcpf2tcpcf6c8s0',
    'service-ats',
    'd9ubvfcpf2tcpcf6c8r0',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('d9ubvfcpf2tcpcf6c8t0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8r0', 'https://api.stawi.org/ats'),
  ('d9ubvfcpf2tcpcf6c8tg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8r0', 'https://api.stawi.org/calendar'),
  ('d9ubvfcpf2tcpcf6c8u0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8r0', 'https://api.stawi.org/profile'),
  ('d9ubvfcpf2tcpcf6c8ug', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8r0', 'https://api.stawi.org/tenancy'),
  ('d9ubvfcpf2tcpcf6c8v0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd9ubvfcpf2tcpcf6c8r0', 'https://api.stawi.org/notification')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
) VALUES (
  'd9ubvfcpf2tcpcf6c8sg', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'd9ubvfcpf2tcpcf6c8rg', 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
) VALUES
  ('d9ubvfcpf2tcpcf6c8vg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8sg', 'service_ats', 'partition_tree'),
  ('d9ubvfcpf2tcpcf6c900', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8sg', 'service_calendar', 'partition_tree')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
) VALUES
  ('d9ubvfcpf2tcpcf6c90g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_dashboard_view'),
  ('d9ubvfcpf2tcpcf6c910', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_job_view'),
  ('d9ubvfcpf2tcpcf6c91g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_job_manage'),
  ('d9ubvfcpf2tcpcf6c920', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_application_view'),
  ('d9ubvfcpf2tcpcf6c92g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_application_manage'),
  ('d9ubvfcpf2tcpcf6c930', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_interview_view'),
  ('d9ubvfcpf2tcpcf6c93g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_interview_manage'),
  ('d9ubvfcpf2tcpcf6c940', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_talent_view'),
  ('d9ubvfcpf2tcpcf6c94g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_talent_manage'),
  ('d9ubvfcpf2tcpcf6c950', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_availability_manage'),
  ('d9ubvfcpf2tcpcf6c95g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_ai_use'),
  ('d9ubvfcpf2tcpcf6c960', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_hire'),
  ('d9ubvfcpf2tcpcf6c96g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c8vg', 'ats_publish'),
  ('d9ubvjcpf2tcrc8moomg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c900', 'calendar_resource_view'),
  ('d9ubvjcpf2tcrc8moon0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c900', 'calendar_resource_manage'),
  ('d9ubvjcpf2tcrc8moong', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c900', 'calendar_availability_manage'),
  ('d9ubvjcpf2tcrc8mooo0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c900', 'calendar_slot_view'),
  ('d9ubvjcpf2tcrc8mooog', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c900', 'calendar_booking_view'),
  ('d9ubvjcpf2tcrc8moop0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd9ubvfcpf2tcpcf6c900', 'calendar_booking_manage')
ON CONFLICT (id) DO NOTHING;

-- Opportunities SPA (prod + dev): product audience for ATS + callback under /ats/.
INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('d9ubvjcpf2tcrc8moopg', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqre0', 'd7gi6lkpf2t67dlsqreg', 'd7gi6lkpf2t67dlsqrgg', 'https://api.stawi.org/ats'),
  ('d9ubvjcpf2tcrc8mooq0', NOW(), NOW(), 1, 'd7gi6lkpf2t67dlsqrh0', 'd7gi6lkpf2t67dlsqrhg', 'd7gi6ncpf2t7oh5akfr0', 'https://api.stawi.org/ats')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

UPDATE public.clients
SET redirect_uris = '{"uris": ["https://opportunities.stawi.org/auth/callback/", "https://opportunities.stawi.org/ats/auth/callback/", "https://accounts.stawi.org/_internal/fedcm-callback"]}',
    modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'd7is2kspf2t7cl19qlp0';

UPDATE public.clients
SET redirect_uris = '{"uris": ["https://opportunities-dev.stawi.org/auth/callback/", "https://opportunities-dev.stawi.org/ats/auth/callback/", "http://localhost:5170/auth/callback/", "http://localhost:5175/auth/callback/", "https://accounts.stawi.org/_internal/fedcm-callback"]}',
    modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'd7is2kspf2t7cl19qlpg';

UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-ats';
