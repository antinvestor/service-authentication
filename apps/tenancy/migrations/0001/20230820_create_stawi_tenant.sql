-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('9bsv0s0hijjg02z5lbjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Stawi',
        'Default base tenant for stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('9bsv0s0hijjg02qk7l1g', '9bsv0s0hijjg02z5lbjg', '9bsv0s0hijjg02qk7l1g',
        'Stawi', 'Default stawi partition to serve the masses',
        '{
          "scope": "openid offline offline_access profile contact",
          "audience": [
            "service_chat_drone",
            "service_chat_gateway",
            "service_devices",
            "service_profile",
            "service_files"
          ],
          "logo_uri": "https://static.stawi.im/logo.png",
          "redirect_uris": [
            "https://app.stawi.im/sso/redirect",
            "com.antinvestor.chat://sso/redirect",
            "http://localhost:5170/sso/redirect"
          ],
          "post_logout_redirect_uris": [
            "https://app.stawi.im/sso/logout"
          ],
          "support_contacts": {
            "msisdn": "+256757546244",
            "email": "info@stawi.im"
          }
        }');

-- Public client for Stawi partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris, properties
) VALUES (
    'd6l82t4pf2t82gudn7tg',
    '9bsv0s0hijjg02z5lbjg',
    '9bsv0s0hijjg02qk7l1g',
    'Stawi',
    'stawi',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_chat_drone","service_chat_gateway","service_devices","service_profile","service_files"]}',
    '{"uris": ["https://app.stawi.im/sso/redirect","com.antinvestor.chat://sso/redirect","http://localhost:5170/sso/redirect"]}',
    '{"logo_uri": "https://static.stawi.im/logo.png", "post_logout_redirect_uris": ["https://app.stawi.im/sso/logout"]}'
) ON CONFLICT (id) DO NOTHING;

