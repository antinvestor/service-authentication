-- ==========================================================================
-- Add default_role to all partition properties that don't already have it.
-- This ensures existing partitions get "user" as their default role,
-- matching the seed data convention.
-- ==========================================================================

UPDATE partitions
SET properties = properties || '{"default_role": "user"}'::jsonb
WHERE properties IS NOT NULL
  AND NOT (properties ? 'default_role');

UPDATE partitions
SET properties = '{"default_role": "user"}'::jsonb
WHERE properties IS NULL;
