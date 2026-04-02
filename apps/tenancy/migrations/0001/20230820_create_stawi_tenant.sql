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
VALUES ('9bsv0s0hijjg02z5lbjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Stawi',
        'Default base tenant for stawi', 'production');
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
VALUES ('9bsv0s0hijjg02qk7l1g', '9bsv0s0hijjg02z5lbjg', '9bsv0s0hijjg02qk7l1g',
        'c2f4j7au6s7f91uqnokg',                          -- parent: System Manager
        'Stawi', 'Default stawi partition to serve the masses', 'true',
        '{
          "default_role": "user",
          "allow_auto_access": true,
          "support_contacts": {
            "msisdn": "+256757546244",
            "email": "info@stawi.im"
          }
        }');

-- Public client for Stawi partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7tg',
    '9bsv0s0hijjg02z5lbjg',
    '9bsv0s0hijjg02qk7l1g',
    'Stawi',
    'd6qbqdkpf2t52mcunf40',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_chat": [],"service_device": [],"service_file": [],"service_profile": []}',
    '{"uris": ["https://app.stawi.im/sso/redirect","com.antinvestor.chat://sso/redirect","http://localhost:5170/sso/redirect"]}',
    'https://static.stawi.im/logo.png',
    '{"uris": ["https://app.stawi.im/sso/logout"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
