-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-- Service account: service_commerce (platform-commerce Cloud Run, antinvestor/service-commerce apps/default)
-- Owns permission namespace service_commerce; Hydra client_id service-commerce.
-- Peers: checkout (hosted payment sessions), ledger (end-of-day posting),
-- notification (buyer/seller messages + template sync), trustage (scheduled
-- workflow registration), tenancy (permission manifest registration).

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'daeltdcpf2t6p29e33eg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_commerce',
    'service-commerce',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'daeltdcpf2t6p29e33f0',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'daeltdcpf2t6p29e33f0',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_commerce',
    'daeltdcpf2t6p29e33fg',
    'service-commerce',
    'daeltdcpf2t6p29e33eg',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- Token audiences this service requests when calling peers.
INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('daeltdcpf2t6p29e33gg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/commerce'),
  ('daeltdcpf2t6p29e33h0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/tenancy'),
  ('daeltdcpf2t6p29e33hg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/profile'),
  ('daeltdcpf2t6p29e33i0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/checkout'),
  ('daeltdcpf2t6p29e33ig', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/ledger'),
  ('daeltdcpf2t6p29e33j0', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/notification'),
  ('daeltdcpf2t6p29e33jg', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/trustage')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
) VALUES (
  'daeltdcpf2t6p29e33g0', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'daeltdcpf2t6p29e33f0', 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
) VALUES
  ('daeltdcpf2t6p29e33k0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33g0', 'service_commerce', 'partition_tree'),
  ('daeltdcpf2t6p29e33kg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33g0', 'service_checkout', 'partition_tree'),
  ('daeltdcpf2t6p29e33l0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33g0', 'service_ledger', 'partition_tree'),
  ('daeltdcpf2t6p29e33lg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33g0', 'service_notification', 'partition_tree'),
  ('daeltdcpf2t6p29e33m0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33g0', 'service_trustage', 'partition_tree')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
) VALUES
  ('daeltdcpf2t6p29e33mg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33k0', 'shop_view'),
  ('daeltdcpf2t6p29e33n0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33k0', 'shops_list'),
  ('daeltdcpf2t6p29e33ng', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33k0', 'product_view'),
  ('daeltdcpf2t6p29e33o0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33k0', 'order_view'),
  ('daeltdcpf2t6p29e33og', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33k0', 'order_manage'),
  ('daeltdcpf2t6p29e33p0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33k0', 'ledger_post'),
  ('daeltdcpf2t6p29e33pg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33kg', 'checkout_session_create'),
  ('daeltdcpf2t6p29e33q0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33kg', 'checkout_session_view'),
  ('daeltdcpf2t6p29e33qg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'ledger_view'),
  ('daeltdcpf2t6p29e33r0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'ledger_manage'),
  ('daeltdcpf2t6p29e33rg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'account_view'),
  ('daeltdcpf2t6p29e33s0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'account_manage'),
  ('daeltdcpf2t6p29e33sg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'transaction_view'),
  ('daeltdcpf2t6p29e33t0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'transaction_manage'),
  ('daeltdcpf2t6p29e33tg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'book_view'),
  ('daeltdcpf2t6p29e33u0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33l0', 'book_manage'),
  ('daeltdcpf2t6p29e33ug', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33lg', 'notification_send'),
  ('daeltdcpf2t6p29e33v0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33lg', 'template_manage'),
  ('daeltdcpf2t6p29e33vg', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33lg', 'template_view'),
  ('daeltdcpf2t6p29e3400', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33m0', 'workflow_view'),
  ('daeltdcpf2t6p29e340g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e33m0', 'workflow_manage')
ON CONFLICT (id) DO NOTHING;

-- Sync the Hydra client so the audiences land in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-commerce';
