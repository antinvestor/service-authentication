-- Enable private_key_jwt with per-service JWKS URIs for seeded in-cluster service clients.

WITH service_jwks (client_id, jwks_uri) AS (
    VALUES
        ('service-authentication', 'http://service-authentication.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-tenancy', 'http://service-tenancy.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-profile', 'http://service-profile.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-settings', 'http://service-settings.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-devices', 'http://service-devices.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-notification', 'http://service-notification.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-notification-integration-africastalking', 'http://service-notification-integration-africastalking.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-notification-integration-emailsmtp', 'http://service-notification-integration-emailsmtp.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-payment', 'http://service-payment.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-payment-jenga', 'http://service-payment-jenga.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-ledger', 'http://service-ledger.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-billing', 'http://service-billing.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-files', 'http://service-files.files-storage.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-chat-drone', 'http://service-chat-drone.chat.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-chat-gateway', 'http://service-chat-gateway.chat.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('foundry', 'http://foundry.foundry.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('gitvault', 'http://gitvault.foundry.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('trustage', 'http://trustage.trustage.svc.cluster.local/.well-known/oauth2-client-jwks.json')
)
UPDATE clients AS c
SET
    token_endpoint_auth_method = 'private_key_jwt',
    properties = jsonb_set(
        COALESCE(c.properties, '{}'::jsonb),
        '{jwks_uri}',
        to_jsonb(service_jwks.jwks_uri),
        true
    )
FROM service_jwks
WHERE c.client_id = service_jwks.client_id;

WITH service_jwks (client_id, jwks_uri) AS (
    VALUES
        ('service-authentication', 'http://service-authentication.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-tenancy', 'http://service-tenancy.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-profile', 'http://service-profile.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-settings', 'http://service-settings.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-devices', 'http://service-devices.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-notification', 'http://service-notification.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-notification-integration-africastalking', 'http://service-notification-integration-africastalking.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-notification-integration-emailsmtp', 'http://service-notification-integration-emailsmtp.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-payment', 'http://service-payment.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-payment-jenga', 'http://service-payment-jenga.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-ledger', 'http://service-ledger.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-billing', 'http://service-billing.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-files', 'http://service-files.files-storage.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-chat-drone', 'http://service-chat-drone.chat.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('service-chat-gateway', 'http://service-chat-gateway.chat.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('foundry', 'http://foundry.foundry.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('gitvault', 'http://gitvault.foundry.svc.cluster.local/.well-known/oauth2-client-jwks.json'),
        ('trustage', 'http://trustage.trustage.svc.cluster.local/.well-known/oauth2-client-jwks.json')
)
UPDATE service_accounts AS sa
SET
    properties = jsonb_set(
        jsonb_set(
            COALESCE(sa.properties, '{}'::jsonb),
            '{token_endpoint_auth_method}',
            '"private_key_jwt"'::jsonb,
            true
        ),
        '{jwks_uri}',
        to_jsonb(service_jwks.jwks_uri),
        true
    )
FROM service_jwks
WHERE sa.client_id = service_jwks.client_id;
