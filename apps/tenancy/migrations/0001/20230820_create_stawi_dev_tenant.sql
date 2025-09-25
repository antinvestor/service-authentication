-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg09bzz6dg', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg', 'Stawi Development', 'Default base tenant for testing and building stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, client_secret, properties)
    VALUES('9bsv0s0hijjg02qks6i0', '9bsv0s3pbdv002o80qfg', '9bsv0s3pbdv002o80qhg',
           'Stawi Development', 'Default Stawi development partition',
           'Sec_Z81B5oqeOKPMBaIxqb',
           '{"scope": "openid offline_access profile contact", "audience": ["service_matrix", "service_profile", "service_files"], "logo_uri": "https://static.stawi.im/logo.png", "redirect_uris": ["https://matrix-dev.stawi.im/_matrix/client/v3/login/sso/callback", "http://localhost:8008/_matrix/client/v3/login/sso/callback", "https://localhost:8448/_matrix/client/v3/login/sso/callback"], "post_logout_redirect_uris": ["https://matrix-dev.stawi.im/_matrix/client/v3/logout", "http://localhost:8008/_matrix/client/v3/logout", "https://localhost:8448/_matrix/client/v3/logout"]}');

