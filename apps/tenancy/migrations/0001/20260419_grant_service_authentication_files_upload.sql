-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0

-- Grants service-authentication the ability to call service-files'
-- UploadContent RPC, which guards on the "content_upload" permission.
--
-- Why: when a user signs in via an external IdP that exposes a profile
-- picture, the auth service emits an async event. The consumer downloads
-- the avatar and uploads it to the files service. Without this grant the
-- upload returns "unauthorised" at the security interceptor.
--
-- We write the new audience entry to BOTH the clients row (used for
-- OAuth2 token minting) and the service_accounts row (used for the
-- authz/Keto tuple projection). Idempotent via COALESCE — the update
-- is a no-op once the audience is already present.

UPDATE clients
SET audiences = COALESCE(audiences, '{}'::jsonb)
    || '{"service_files": ["content_upload"]}'::jsonb
WHERE client_id = 'service-authentication';

UPDATE service_accounts
SET audiences = COALESCE(audiences, '{}'::jsonb)
    || '{"service_files": ["content_upload"]}'::jsonb
WHERE client_id = 'service-authentication';
