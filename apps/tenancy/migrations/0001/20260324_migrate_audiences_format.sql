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
