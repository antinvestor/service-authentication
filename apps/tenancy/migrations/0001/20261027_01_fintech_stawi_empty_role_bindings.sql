-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech stawi: drop role bindings left empty by the narrowing (2026-10-27).
--
-- 20261026_09 narrowed service_stawi's role bindings to the permissions its
-- manifest still declares, which left the viewer role bound to nothing. The
-- manifest binds no viewer role at all, and registration treats a stored role
-- the manifest omits as a removal, so the stawi setup Job's registration was
-- refused with 409. An empty binding grants nothing; dropping it changes no
-- access. The guard keeps a re-run a no-op.

UPDATE service_namespaces
SET role_bindings = (
        SELECT COALESCE(jsonb_object_agg(role, perms), '{}'::jsonb)
        FROM jsonb_each(role_bindings) AS rb(role, perms)
        WHERE jsonb_array_length(perms) > 0
    ),
    generation = generation + 1,
    modified_at = CURRENT_TIMESTAMP
WHERE namespace = 'service_stawi'
  AND EXISTS (
      SELECT 1 FROM jsonb_each(role_bindings) AS rb(role, perms) WHERE jsonb_array_length(perms) = 0
  );
