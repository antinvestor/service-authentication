-- to quickly generate xids use : https://play.golang.org/p/xSMJJ9G9Lt_-

-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg02qks6dg', '9bsv0s0hijjg02qks6dg', '9bsv0s0hijjg02qks6i0', 'Chamamobile Development', 'Default base tenant for testing and building chamamobile');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, client_secret, properties)
    VALUES('9bsv0s0hijjg02qks6i0', '9bsv0s0hijjg02qks6dg', '9bsv0s0hijjg02qks6i0',
           'Chamamobile Development', 'Default chamamobile development partition in chamamobile development',
           'Sec_Z81B5oqeOKPMBaIxqb',
           '{"scope": "openid offline_access profile contact", "audience": ["service_matrix", "service_profile", "service_stawi_api", "service_files"], "logo_uri": "https://static.chamamobile.com/logo.png", "redirect_uris": ["https://chamamobile.com/_matrix/client/v3/login/sso/callback", "http://localhost:8008/_matrix/client/v3/login/sso/callback", "https://localhost:8448/_matrix/client/v3/login/sso/callback"]}');

