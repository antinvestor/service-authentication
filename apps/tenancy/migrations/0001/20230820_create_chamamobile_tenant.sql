-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg02qks6jg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Chamamobile', 'Default base tenant for testing and building chamamobile');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, client_secret, properties)
    VALUES('9bsv0s0hijjg02qks6kg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
           'Chamamobile', 'Default chamamobile partition to serve the masses', 'Sec_oXrpEHfunPu6r4A58f',
           '{"scope": "openid offline_access profile contact", "audience": ["service_matrix", "service_profile", "service_stawi_api", "service_files"], "logo_uri": "https://static.chamamobile.com/logo.png", "redirect_uris": ["https://matrix.chamamobile.com/_matrix/client/v3/login/sso/callback"], "post_logout_redirect_uris": ["https://matrix.chamamobile.com/_matrix/client/v3/logout"]}');

