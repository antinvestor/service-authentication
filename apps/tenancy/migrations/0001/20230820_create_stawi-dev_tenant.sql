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

-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment)
VALUES ('9bsv0s0hijjg02z5lr4g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Stawi AI Builder',
        'Default base tenant for stawi', 'production');
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('9bsv0s0hid5g02qkl7gjg', '9bsv0s0hijjg02z5lr4g', '9bsv0s0hid5g02qkl7gjg',
        'c2f4j7au6s7f91uqnokg',                          -- parent: Thesa (origin)
        'Stawi AI Builder', 'Default stawi ai builder partition to serve the masses', 'true',
        '{
          "default_role": "user",
          "allow_auto_access": true,
          "support_contacts": {
            "msisdn": "+256757546244",
            "email": "info@stawi.im"
          }
        }');

-- Standard partition roles (owner, admin, member)
INSERT INTO partition_roles (id, created_at, modified_at, version, tenant_id, partition_id, name, is_default, properties)
VALUES
    ('9bsv0s0hid5g02qkl7h0', NOW(), NOW(), 1,
     '9bsv0s0hijjg02z5lr4g', '9bsv0s0hid5g02qkl7gjg',
     'owner', false, '{"description": "Full control across all services"}'),
    ('9bsv0s0hid5g02qkl7h1', NOW(), NOW(), 1,
     '9bsv0s0hijjg02z5lr4g', '9bsv0s0hid5g02qkl7gjg',
     'admin', false, '{"description": "Manage partitions, access, roles, and pages"}'),
    ('9bsv0s0hid5g02qkl7h2', NOW(), NOW(), 1,
     '9bsv0s0hijjg02z5lr4g', '9bsv0s0hid5g02qkl7gjg',
     'member', true, '{"description": "Read-only access, auto-assigned on access creation"}')
ON CONFLICT (id) DO NOTHING;

-- Public client for Stawi AI Builder partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7ug',
    '9bsv0s0hijjg02z5lr4g',
    '9bsv0s0hid5g02qkl7gjg',
    'Stawi AI Builder',
    'd6qbqdkpf2t52mcunf50',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_device": [],"service_profile": [],"service_file": []}',
    '{"uris": ["https://stawi.dev/auth/callback"]}',
    'https://static.stawi.dev/logo.png',
    '{"uris": ["https://stawi.dev"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
