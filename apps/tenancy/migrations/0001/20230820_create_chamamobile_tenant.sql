-- to quickly generate xids use : https://play.golang.org/p/xSMJJ9G9Lt_-

-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg02qks6jg', '9bsv0s0hijjg02qks6jg', '9bsv0s0hijjg02qks6kg', 'Chamamobile', 'Default base tenant for testing and building chamamobile');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, client_secret, properties)
    VALUES('9bsv0s0hijjg02qks6kg', '9bsv0s0hijjg02qks6jg', '9bsv0s0hijjg02qks6kg',
           'Chamamobile', 'Default chamamobile partition to serve the masses', 'Sec_oXrpEHfunPu6r4A58f',
           '{"scope": "openid offline_access profile contact", "audience": ["service_matrix", "service_profile", "service_stawi_api", "service_files"], "logo_uri": "https://static.chamamobile.com/logo.png", "redirect_uris": ["https://chamamobile.com/_matrix/client/v3/login/sso/callback"]}');

