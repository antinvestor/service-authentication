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
-- Migrate audiences from legacy {"namespaces": [...]} to new map format
-- ==========================================================================
--
-- Old format: {"namespaces": ["service_profile", "service_tenancy"]}
-- New format: {"service_profile": [], "service_tenancy": []}
--
-- Each namespace becomes a top-level key with an empty array value,
-- meaning bridge-tuple-only access (ns#service ← tenancy_access#service).
--
-- This migration converts all existing rows in both clients and
-- service_accounts tables that still use the legacy format.
-- ==========================================================================

-- Convert clients.audiences
UPDATE clients
SET audiences = (
    SELECT jsonb_object_agg(ns.value::text, '[]'::jsonb)
    FROM jsonb_array_elements(audiences->'namespaces') AS ns(value)
)
WHERE audiences ? 'namespaces'
  AND jsonb_typeof(audiences->'namespaces') = 'array';

-- Convert service_accounts.audiences
UPDATE service_accounts
SET audiences = (
    SELECT jsonb_object_agg(ns.value::text, '[]'::jsonb)
    FROM jsonb_array_elements(audiences->'namespaces') AS ns(value)
)
WHERE audiences ? 'namespaces'
  AND jsonb_typeof(audiences->'namespaces') = 'array';
