-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_notification_whatsapp
-- WhatsApp notification integration service account (Meta Cloud API webhook and send worker)

INSERT INTO clients (
    id, tenant_id, partition_id, name, client_id, client_secret,
    type, grant_types, scopes,
    token_endpoint_auth_method, service_account_id, properties
) VALUES (
    'daend44pf2t8c15rs7vg',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'sa-service_notification_whatsapp',
    'service-notification-integration-whatsapp',
    '',
    'internal',
    '{"types": ["client_credentials"]}',
    'system_int openid',
    'private_key_jwt',
    'daend44pf2t8c15rs80g',
    '{"jwks_uri": "https://oauth2.stawi.org/.well-known/jwks.json"}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_accounts (
    id, tenant_id, partition_id, name, profile_id,
    client_id, client_ref, type, properties
) VALUES (
    'daend44pf2t8c15rs80g',
    'c2f4j7au6s7f91uqnojg',
    'c2f4j7au6s7f91uqnokg',
    'service_notification_whatsapp',
    'daenc7kpf2t8pa1q04hg',
    'service-notification-integration-whatsapp',
    'daend44pf2t8c15rs7vg',
    'internal',
    '{}'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daend4kpf2t8cmavmue0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs7vg', 'https://api.stawi.org/notification') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daend4kpf2t8cmavmueg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs7vg', 'https://api.stawi.org/profile') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daend4kpf2t8cmavmuf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs7vg', 'https://api.stawi.org/settings') ON CONFLICT (id) DO NOTHING;

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('daend4kpf2t8cmavmufg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs7vg', 'https://api.stawi.org/tenancy') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES ('daend44pf2t8c15rs810', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs80g', 1, 1, 0, 'pending', 0) ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daend4kpf2t8cmavmug0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs810', 'service_notification', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmugg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'notification_release') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'notification_search') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuhg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'notification_send') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmui0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'notification_status_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'notification_status_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'template_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmujg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmug0', 'template_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daend4kpf2t8cmavmuk0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs810', 'service_profile', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmukg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'address_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmul0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'contact_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmulg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'profile_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmum0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'profile_merge') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmumg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'profile_update') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmun0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'profile_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmung', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'relationship_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuo0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'relationship_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuog', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'roster_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmup0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmuk0', 'roster_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daend4kpf2t8cmavmupg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs810', 'service_setting', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuq0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmupg', 'setting_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmupg', 'setting_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('daend4kpf2t8cmavmur0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend44pf2t8c15rs810', 'service_tenancy', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmurg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'access_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmus0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'access_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmusg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'client_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmut0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'client_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmutg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'page_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuu0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'page_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'partition_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuv0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'partition_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmuvg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'permission_grant') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmv00', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'role_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmv0g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'service_account_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmv10', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'service_account_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmv1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'tenant_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('daend4kpf2t8cmavmv20', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daend4kpf2t8cmavmur0', 'tenant_view') ON CONFLICT (id) DO NOTHING;
