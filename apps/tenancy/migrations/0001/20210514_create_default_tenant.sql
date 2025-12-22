-- to quickly generate xids use : https://play.golang.org/p/xSMJJ9G9Lt_-

-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'System Manager',
        'Default base tenant that all others build on');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'System manager',
        'Default base partition in the base tenant', '{
    "scope": "openid offline offline_access profile contact",
    "audience": [
      "service_tenancy",
      "service_devices",
      "service_profile",
      "service_notification",
      "service_payments",
      "service_files",
      "service_ledger"
    ],
    "logo_uri": "https://static.antinvestor.com/logo.png",
    "redirect_uris": [
      "https://admin.antinvestor.com/auth/callback"
    ],
    "post_logout_redirect_uris": [
      "https://admin.antinvestor.com/"
    ],
    "support_contacts": {
      "msisdn": "+256757546244",
      "email": "info@antinvestor.com"
    }
  }');

