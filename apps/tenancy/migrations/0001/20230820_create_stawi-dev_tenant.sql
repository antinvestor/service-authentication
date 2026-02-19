-- Default base partition
INSERT INTO tenants (id, tenant_id, partition_id, name, description)
VALUES ('9bsv0s0hijjg02z5lr4g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'Stawi AI Builder',
        'Default base tenant for stawi');
INSERT INTO partitions (id, tenant_id, partition_id, name, description, properties)
VALUES ('9bsv0s0hid5g02qkl7gjg', '9bsv0s0hijjg02z5lr4g', '9bsv0s0hid5g02qkl7gjg',
        'Stawi AI Builder', 'Default stawi ai builder partition to serve the masses',
        '{
          "scope": "openid offline offline_access profile contact",
          "audience": [
          "service_trustage",
          "service_foundry",
          "service_devices",
          "service_profile",
          "service_files"
          ],
          "logo_uri": "https://static.stawi.dev/logo.png",
          "redirect_uris": [
            "https://stawi.dev/auth/callback"
          ],
          "post_logout_redirect_uris": [
            "https://stawi.dev"
          ],
          "support_contacts": {
            "msisdn": "+256757546244",
            "email": "info@stawi.im"
          }
        }');
