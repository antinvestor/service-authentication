
-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description) VALUES('9bsv0s4qlfug02s9at8g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'My Lost ID', 'Default tenant that manages authentication related to my lost id');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
    VALUES('9bsv0s4qlfug02s9at9g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'My Lost Id', 'Default partition to manage access to my lost id', '{"scope": "openid offline offline_access profile contact", "audience": ["service_partition", "service_profile", "service_notification", "service_files", "service_ledger", "service_mylostid", "service_ocr"], "logo_uri": "https://static.mylostid.com/logo.png", "redirect_uris": ["https://mylostid.com/callback.html"]}');

