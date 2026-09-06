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
-- Service account: service_procurement (platform-procurement Cloud Run, antinvestor/service-commerce apps/procurement)
-- Owns permission namespace service_procurement; Hydra client_id service-procurement.
-- Peers: tenancy (permission manifest registration).

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'daeltdcpf2t6p29e3410',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_procurement',
    'service-procurement',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'daeltdcpf2t6p29e341g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'daeltdcpf2t6p29e341g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_procurement',
    'daeltdcpf2t6p29e3420',
    'service-procurement',
    'daeltdcpf2t6p29e3410',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

-- Token audiences this service requests when calling peers.
INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('daeltdcpf2t6p29e3430', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e3410', 'https://api.stawi.org/procurement'),
  ('daeltdcpf2t6p29e343g', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e3410', 'https://api.stawi.org/tenancy'),
  ('daeltdcpf2t6p29e3440', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e3410', 'https://api.stawi.org/profile')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_policies (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  service_account_id, schema_version, generation, applied_generation,
  status, retry_count, last_error_code, last_error, next_attempt_at, synced_at
) VALUES (
  'daeltdcpf2t6p29e342g', NOW(), NOW(), '', '', 1,
  'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL,
  'daeltdcpf2t6p29e341g', 1, 1, 0,
  'pending', 0, '', '', NULL, NULL
) ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
) VALUES
  ('daeltdcpf2t6p29e344g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e342g', 'service_procurement', 'partition_tree')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
) VALUES
  ('daeltdcpf2t6p29e3450', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'supplier_view'),
  ('daeltdcpf2t6p29e345g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'supplier_manage'),
  ('daeltdcpf2t6p29e3460', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'purchase_order_view'),
  ('daeltdcpf2t6p29e346g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'purchase_order_create'),
  ('daeltdcpf2t6p29e3470', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'purchase_order_submit'),
  ('daeltdcpf2t6p29e347g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'purchase_order_cancel'),
  ('daeltdcpf2t6p29e3480', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'goods_receipt_view'),
  ('daeltdcpf2t6p29e348g', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e344g', 'goods_receipt_create')
ON CONFLICT (id) DO NOTHING;

-- Sync the Hydra client so the audiences land in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-procurement';
