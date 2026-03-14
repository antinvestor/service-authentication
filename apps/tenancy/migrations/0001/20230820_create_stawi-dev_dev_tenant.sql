-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjghdbz96dg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg', 'Stawi AI Builder Development', 'Default base tenant for testing and building stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
    VALUES('9bsv0s0hijjb83qksr20', '9bsv0s0hijjghdbz96dg', '9bsv0s0hijjb83qksr20',
           'Stawi AI Builder Development', 'Default Stawi development partition',
           '{
            "support_contacts": {
              "msisdn": "+256757546244",
              "email": "info@stawi.dev"
            }
           }');

-- Public client for Stawi AI Builder Development partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris,
    logo_uri, post_logout_redirect_uris, token_endpoint_auth_method
) VALUES (
    'd6l82t4pf2t82gudn7v0',
    '9bsv0s0hijjghdbz96dg',
    '9bsv0s0hijjb83qksr20',
    'Stawi AI Builder Development',
    'd6qbqdkpf2t52mcunf5g',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_trustage","service_foundry","service_device","service_profile","service_files"]}',
    '{"uris": ["https://dev.stawi.dev/auth/callback","https://localhost:5170/auth/callback"]}',
    'https://static.stawi.dev/logo.png',
    '{"uris": ["https://dev.stawi.dev","https://localhost:5170"]}',
    'none'
) ON CONFLICT (id) DO NOTHING;
