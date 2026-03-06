-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg09bzz6dg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg', 'Stawi Development', 'Default base tenant for testing and building stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
    VALUES('9bsv0s0hijjg02qks6i0', '9bsv0s0hijjg09bzz6dg', '9bsv0s0hijjg02qks6i0',
           'Stawi Development', 'Default Stawi development partition',
           '{
             "scope": "openid offline offline_access profile contact",
             "audience": [
               "service_chat_drone",
               "service_chat_gateway",
               "service_devices",
               "service_profile",
               "service_files"
             ],
             "redirect_uris": [
               "https://app-dev.stawi.im/sso/redirect",
               "com.antinvestor.chat://sso/redirect",
               "https://localhost:5170/sso/redirect"
             ],
            "support_contacts": {
              "msisdn": "+256757546244",
              "email": "info@stawi.im"
            }
           }');

-- Public client for Stawi Development partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method, parent_ref
) VALUES (
    'd6l82t4pf2t82gudn7u0',
    '9bsv0s0hijjg09bzz6dg',
    '9bsv0s0hijjg02qks6i0',
    'Stawi Development',
    'stawi_dev',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_chat_drone","service_chat_gateway","service_devices","service_profile","service_files"]}',
    '{"uris": ["https://app-dev.stawi.im/sso/redirect","com.antinvestor.chat://sso/redirect","https://localhost:5170/sso/redirect"]}',
    'https://static.stawi.im/logo.png',
    '{"uris": ["https://app-dev.stawi.im/sso/logout","com.antinvestor.chat://sso/logout","https://localhost:5170/sso/logout"]}',
    'none',
    '9bsv0s0hijjg02qks6i0'                        -- parent_ref → Partition.ID (Stawi Development)
) ON CONFLICT (id) DO NOTHING;

