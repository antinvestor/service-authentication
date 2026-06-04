-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: rename the "Stawi Jobs" tenant/partition/client display names to
-- "Stawi Opportunities" for consistency with the opportunities.stawi.org
-- rebrand. The seeds use ON CONFLICT (id) DO NOTHING, so the renamed seed only
-- affects fresh installs; this migration updates already-seeded clusters.
--
-- Idempotent: after the rename no row matches LIKE 'Stawi Jobs%', so re-runs
-- are no-ops. Clearing clients.synced_at forces the next sync cycle to push the
-- new client_name to Hydra. Affected xids (see IDS.md):
--   tenants     d7gi6lkpf2t67dlsqre0, d7gi6lkpf2t67dlsqrh0
--   partitions  d7gi6lkpf2t67dlsqreg, d7gi6lkpf2t67dlsqrhg
--   clients     d7gi6lkpf2t67dlsqrgg, d7gi6ncpf2t7oh5akfr0

UPDATE tenants
SET name = replace(name, 'Stawi Jobs', 'Stawi Opportunities'),
    description = replace(description, 'job board', 'opportunities')
WHERE name LIKE 'Stawi Jobs%';

UPDATE partitions
SET name = replace(name, 'Stawi Jobs', 'Stawi Opportunities'),
    description = replace(description, 'job board', 'opportunities')
WHERE name LIKE 'Stawi Jobs%';

UPDATE clients
SET name = replace(name, 'Stawi Jobs', 'Stawi Opportunities'),
    synced_at = NULL
WHERE name LIKE 'Stawi Jobs%';
