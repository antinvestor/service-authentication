-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg02qks6jg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Stawi', 'Default base tenant for stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, client_secret, properties)
    VALUES('9bsv0s0hijjg02qk7l1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
           'Stawi', 'Default stawi partition to serve the masses', 'Sec_oZemEHfunPu6r4AJr2',
           '{"scope": "openid offline_access profile contact", "audience": ["service_matrix", "service_profile", "service_files"], "logo_uri": "https://static.stawi.im/logo.png", "redirect_uris": ["https://stawi.im/_matrix/client/v3/login/sso/callback"], "post_logout_redirect_uris": ["https://stawi.im/_matrix/client/v3/logout"]}');

