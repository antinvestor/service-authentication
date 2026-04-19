-- Copyright 2023-2026 Ant Investor Ltd
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0

-- Appends the FedCM internal-callback URI to every authorization_code client.
--
-- Why: when the authentication service's id_assertion_endpoint drives a
-- headless Hydra flow, it uses <FEDCM_PUBLIC_ORIGIN>/_internal/fedcm-callback
-- as the OAuth2 redirect_uri. Hydra validates redirect_uris per client, so
-- each public client that wants to be usable via FedCM needs this URI in
-- its registered list. The callback is never reached by the browser — the
-- headless driver intercepts the redirect server-side — so registering it
-- does not affect the user-facing OAuth2 flows.
--
-- Only public/confidential clients that use authorization_code need the
-- URI. client_credentials service accounts never redirect and are skipped.
--
-- Idempotent: the WHERE clause guards against duplicate appends.

UPDATE clients
SET redirect_uris = jsonb_set(
        redirect_uris,
        '{uris}',
        COALESCE(redirect_uris -> 'uris', '[]'::jsonb)
            || '["https://accounts.stawi.org/_internal/fedcm-callback"]'::jsonb
    )
WHERE (grant_types -> 'types') @> '["authorization_code"]'::jsonb
  AND NOT COALESCE(redirect_uris -> 'uris', '[]'::jsonb)
        @> '["https://accounts.stawi.org/_internal/fedcm-callback"]'::jsonb;
