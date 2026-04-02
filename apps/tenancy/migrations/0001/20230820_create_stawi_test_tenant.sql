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
INSERT INTO tenants (id, tenant_id, partition_id, name, description, environment) VALUES('9bsv0s0hijjg09bzz6dg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg', 'Stawi Development', 'Default base tenant for testing and building stawi', 'staging');
INSERT INTO partitions (id, tenant_id, partition_id, parent_id, name, description, allow_auto_access, properties)
    VALUES('9bsv0s0hijjg02qks6i0', '9bsv0s0hijjg09bzz6dg', '9bsv0s0hijjg02qks6i0',
           '9bsv0s3pbdv002o80qhg',                        -- parent: Dev Backoffice
           'Stawi Development', 'Default Stawi development partition', 'true',
           '{
            "default_role": "user",
            "allow_auto_access": true,
            "support_contacts": {
              "msisdn": "+256757546244",
              "email": "info@stawi.im"
            }
           }');

-- Public client for Stawi Development partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7u0',
    '9bsv0s0hijjg09bzz6dg',
    '9bsv0s0hijjg02qks6i0',
    'Stawi Development',
    'd6qbqdkpf2t52mcunf4g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"service_chat_drone": [],"service_chat_gateway": [],"service_device": [],"service_profile": [],"service_file": []}',
    '{"uris": ["https://app-dev.stawi.im/sso/redirect","com.antinvestor.chat://sso/redirect","https://localhost:5170/sso/redirect"]}',
    'https://static.stawi.im/logo.png',
    '{"uris": ["https://app-dev.stawi.im/sso/logout","com.antinvestor.chat://sso/logout","https://localhost:5170/sso/logout"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
