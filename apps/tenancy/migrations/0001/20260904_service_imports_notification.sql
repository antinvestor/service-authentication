-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_imports — notification audience + grants.
-- The imports setup job registers its message templates with
-- service-notification (client/templates.Sync) and the runtime sends
-- customer/staff messages, which needs a token with the /notification
-- audience and template_manage + notification_send in namespace
-- service_notification.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dadbol4pf2t2qn50nh0g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uap0', 'https://api.stawi.org/notification') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dadbol4pf2t2qn50nh10', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daaltq4pf2tb6me3uaqg', 'service_notification', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dadbol4pf2t2qn50nh1g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dadbol4pf2t2qn50nh10', 'template_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dadbol4pf2t2qn50nh20', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dadbol4pf2t2qn50nh10', 'notification_send') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'daaltq4pf2tb6me3uaqg';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'imports';
