-- Set jwks_uri in properties for all private_key_jwt clients that don't have it.
-- Each service exposes /.well-known/oauth2-client-jwks.json via Frame's workload API.
-- Without jwks_uri, Hydra rejects private_key_jwt client registrations with 400.

-- Service authentication (auth namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-authentication.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-authentication' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service tenancy (auth namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-tenancy.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-tenancy' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service profile (profile namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-profile.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-profile' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service devices (profile namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-devices.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-devices' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service settings (profile namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-settings.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-settings' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service notification (notifications namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-notification.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-notification' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service notification integrations (notifications namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-notification-integration-africastalking.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-notification-integration-africastalking' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-notification-integration-emailsmtp.notifications.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-notification-integration-emailsmtp' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service payment (payments namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-payment.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-payment' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-payment-jenga.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-payment-jenga' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service billing (payments namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-billing.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-billing' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service ledger (payments namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-ledger.payments.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-ledger' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Service files (files-storage namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-files.files.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-files' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Chat services (chat namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-chat-drone.chat.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-chat-drone' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-chat-gateway.chat.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'service-chat-gateway' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Foundry services (foundry namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://foundry.foundry.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'foundry' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://gitvault.foundry.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'gitvault' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Trustage (trustage namespace)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://trustage.trustage.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'trustage' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Synchronize partitions (uses authentication service signer)
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-authentication.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'synchronize-partitions' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);

-- Dev synchronize partitions
UPDATE clients SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-authentication.auth.svc.cluster.local/.well-known/oauth2-client-jwks.json"}'::jsonb
WHERE client_id = 'dev_synchronize_partitions' AND token_endpoint_auth_method = 'private_key_jwt' AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);
