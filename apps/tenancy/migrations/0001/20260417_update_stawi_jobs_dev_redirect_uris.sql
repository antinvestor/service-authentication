--- Copyright 2023-2026 Ant Investor Ltd
---
--- Licensed under the Apache License, Version 2.0 (the "License");
--- you may not use this file except in compliance with the License.
--- You may obtain a copy of the License at
---
---      http://www.apache.org/licenses/LICENSE-2.0
---
--- Unless required by applicable law or agreed to in writing, software
--- distributed under the License is distributed on an "AS IS" BASIS,
--- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--- See the License for the specific language governing permissions and
--- limitations under the License.

-- ==========================================================================
-- PATCH: Stawi Jobs Development client redirect URIs
-- ==========================================================================
--
-- The Stawi Jobs UI dev server was moved from port 1313 (Hugo default) to
-- 5170. Replace the old localhost:1313 entries with localhost:5170 in the
-- staging client's registered redirect_uris and post_logout_redirect_uris
-- so local sign-in no longer fails with redirect_uri_mismatch.
--
-- Idempotent — re-runs produce the same final state.
-- ==========================================================================

UPDATE clients
SET
    redirect_uris = '{"uris": ["https://jobs-dev.stawi.org/auth/callback/", "http://localhost:5170/auth/callback/"]}',
    post_logout_redirect_uris = '{"uris": ["https://jobs-dev.stawi.org/", "http://localhost:5170/"]}'
WHERE id = 'd7gi6ncpf2t7oh5akfr0';  -- staging: Stawi Jobs Development client
