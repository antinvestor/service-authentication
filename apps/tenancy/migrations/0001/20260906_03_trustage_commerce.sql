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
-- Service account: trustage — commerce audience + grants for scheduled commerce workflows.
-- The commerce setup job registers commerce.reconcile_payments and
-- commerce.end_of_day_ledger in trustage; trustage calls back into
-- https://api.stawi.org/commerce with its own service token, which needs the
-- /commerce audience and ledger_post (+ shops_list) in namespace service_commerce.

INSERT INTO public.oauth_client_recipients (
  id, created_at, modified_at, version, tenant_id, partition_id, client_ref, resource_audience
) VALUES
  ('daeltdcpf2t6p29e349g', NOW(), NOW(), 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/commerce')
ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO public.service_account_authorization_grants (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  policy_id, namespace, scope
) VALUES
  ('daeltdcpf2t6p29e3490', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'd94lkmcpf2t39vdkp1f0', 'service_commerce', 'partition_tree')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.service_account_authorization_permissions (
  id, created_at, modified_at, created_by, modified_by, version,
  tenant_id, partition_id, access_id, deleted_at,
  grant_id, permission
) VALUES
  ('daeltdcpf2t6p29e34a0', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e3490', 'ledger_post'),
  ('daeltdcpf2t6p29e34ag', NOW(), NOW(), '', '', 1, 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', '', NULL, 'daeltdcpf2t6p29e3490', 'shops_list')
ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp1f0';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'trustage';
