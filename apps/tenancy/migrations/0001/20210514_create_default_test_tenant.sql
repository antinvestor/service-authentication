-- Test base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg', 'Testing Manager',
        'Default test tenant that all others build on');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('9bsv0s3pbdv002o80qhg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg', 'Dev Backoffice',
        'default dev partition for test tenants', '{
    "scope": "openid offline offline_access profile contact",
    "token_endpoint_auth_method": "none",
    "audience": [
      "service_tenancy",
      "service_devices",
      "service_profile",
      "service_notification",
      "service_files",
      "service_ledger"
    ],
    "logo_uri": "https://static.antinvestor.com/logo.png",
    "redirect_uris": [
      "http://localhost:5173/auth/callback",
      "https://admin-dev.antinvestor.com/auth/callback"
    ],
    "post_logout_redirect_uris": [
      "http://localhost:5173/",
      "https://admin-dev.antinvestor.com/"
    ],
    "support_contacts": {
      "msisdn": "+256757546244",
      "email": "info@antinvestor.com"
    }
  }');

-- Public client for Dev Backoffice partition (user authorization_code flows)
INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id,
    type, grant_types, response_types, scopes, audiences, redirect_uris, properties
) VALUES (
    'd6l82t4pf2t82gudn7sg',
    '9bsv0s3pbdv002o80qfg',
    '9bsv0s3pbdv002o80qhg',
    'Dev Backoffice',
    'dev_backoffice',
    'public',
    '{"types": ["authorization_code","refresh_token"]}',
    '{"types": ["code"]}',
    'openid offline_access profile',
    '{"namespaces": ["service_tenancy","service_devices","service_profile","service_notifications"]}',
    '{"uris": ["http://localhost:5173/auth/callback","https://admin-dev.antinvestor.com/auth/callback"]}',
    '{"logo_uri": "https://static.antinvestor.com/logo.png", "post_logout_redirect_uris": ["http://localhost:5173/","https://admin-dev.antinvestor.com/"]}'
) ON CONFLICT (id) DO NOTHING;

