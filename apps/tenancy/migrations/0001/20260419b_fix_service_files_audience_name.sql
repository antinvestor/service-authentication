-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0

-- Fixes a naming mismatch introduced by the earlier grant migration.
--
-- The files service's Keto/OPL namespace and jwtVerifyAudience are both
-- "service_file" (singular) — source of truth is
-- service-files/proto/files/v1/files.proto "namespace: \"service_file\"".
--
-- The earlier grant wrote the audience under the key "service_files"
-- (plural) which does NOT match any registered namespace, so the authz
-- sync event fails with NotFound and never lands a tuple, and any JWT
-- minted with "service_files" in aud is rejected by service-files.
--
-- This migration:
--   1. Drops the stray "service_files" key on the service-authentication
--      client and SA rows (if present).
--   2. Re-adds the permission under the canonical "service_file" key.
--
-- Idempotent via COALESCE and the "- 'key'" JSONB delete operator.

UPDATE clients
SET audiences = (COALESCE(audiences, '{}'::jsonb) - 'service_files')
    || '{"service_file": ["content_upload"]}'::jsonb
WHERE client_id = 'service-authentication';

UPDATE service_accounts
SET audiences = (COALESCE(audiences, '{}'::jsonb) - 'service_files')
    || '{"service_file": ["content_upload"]}'::jsonb
WHERE client_id = 'service-authentication';
