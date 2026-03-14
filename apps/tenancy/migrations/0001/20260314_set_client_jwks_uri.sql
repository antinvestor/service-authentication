-- Set jwks_uri for all private_key_jwt clients that don't have it yet.
-- All services use the same Hydra public JWKS endpoint for key verification.
-- Without jwks_uri, Hydra rejects private_key_jwt client registrations with 400.
UPDATE clients
SET properties = COALESCE(properties, '{}'::jsonb) || '{"jwks_uri": "http://service-authentication-oauth2-hydra-public.auth.svc.cluster.local:4444/.well-known/jwks.json"}'::jsonb
WHERE token_endpoint_auth_method = 'private_key_jwt'
  AND (properties IS NULL OR properties->>'jwks_uri' IS NULL);
