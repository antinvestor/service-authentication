-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s0hijjg02z5lbjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Stawi', 'Default base tenant for stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
    VALUES('9bsv0s0hijjg02qk7l1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg',
           'Stawi', 'Default stawi partition to serve the masses',
           '{"scope": "openid offline_access profile contact", "audience": ["service_chat_drone","service_chat_gateway", "service_devices", "service_profile", "service_files"], "logo_uri": "https://static.stawi.im/logo.png", "redirect_uris": ["https://app.stawi.im/sso/callback", "http://localhost:5170"], "post_logout_redirect_uris": ["https://app.stawi.im/sso/logout"]}');

