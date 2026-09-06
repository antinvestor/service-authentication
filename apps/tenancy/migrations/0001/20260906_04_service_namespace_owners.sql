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

-- Permission manifest registration only accepts a manifest from the service
-- account that owns the namespace: the account name must equal the namespace
-- (or the client_id with hyphens as underscores). Two accounts were seeded
-- with names that can never satisfy that for the namespaces their protos
-- declare, so service_checkout and service_trustage were never registered and
-- no grant on them could be materialised into Keto:
--
--   trustage                 (client trustage)                 → service_trustage
--   service_payment_checkout (client service-payment-checkout) → service_checkout
--
-- Rename the accounts to their namespaces. client_id, keys and tokens are
-- untouched; the name is only used for namespace ownership.
UPDATE public.service_accounts
SET name = 'service_trustage', modified_at = NOW()
WHERE client_id = 'trustage' AND name = 'trustage';

UPDATE public.service_accounts
SET name = 'service_checkout', modified_at = NOW()
WHERE client_id = 'service-payment-checkout' AND name = 'service_payment_checkout';
