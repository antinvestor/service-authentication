--- Copyright 2023-2026 Ant Investor Ltd
---
--- Licensed under the Apache License, Version 2.0 (the "License");
--- you may not use this file except in compliance with the License.
--- You may obtain a copy of the License at
---
---      http://www.apache.org/licenses/LICENSE-2.0
---
--- Unless required by applicable law or agreed to in writing, software
--- distributed under the License is distributed on an "AS IS" BASIS,
--- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--- See the License for the specific language governing permissions and
--- limitations under the License.

-- Resolve placeholder profile_ids in service_accounts to the static xid
-- profile IDs from the profile service migration (20260331_bootstrap_profiles.sql).
-- This eliminates the need for runtime bot profile resolution via the
-- profile service API.

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij40'
WHERE profile_id = 'service_authentication' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij4g'
WHERE profile_id = 'service_profile' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij50'
WHERE profile_id = 'service_tenancy' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij5g'
WHERE profile_id = 'service_notification' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij60'
WHERE profile_id = 'service_device' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij6g'
WHERE profile_id = 'service_setting' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij70'
WHERE profile_id = 'service_payment' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij7g'
WHERE profile_id = 'service_payment_jenga' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij80'
WHERE profile_id = 'service_ledger' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij8g'
WHERE profile_id = 'service_billing' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij90'
WHERE profile_id = 'service_file' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ij9g'
WHERE profile_id = 'service_chat_drone' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ija0'
WHERE profile_id = 'service_chat_gateway' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ijag'
WHERE profile_id = 'foundry' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ijb0'
WHERE profile_id = 'gitvault' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ijbg'
WHERE profile_id = 'trustage' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ijc0'
WHERE profile_id = 'service_notification_africastalking' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ijcg'
WHERE profile_id = 'service_notification_emailsmtp' AND deleted_at IS NULL;

UPDATE service_accounts SET profile_id = 'd75qclkpf2t1uum8ijd0'
WHERE profile_id = 'service_lender' AND deleted_at IS NULL;
