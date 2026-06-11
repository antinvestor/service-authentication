-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: re-parent the Thesa Development staging partition onto the
-- platform root partition on clusters where the original seed
-- (20260604_partition_thesa_staging.sql) was applied with parent_id
-- pointing at the partition itself.
--
-- The seed used INSERT ... ON CONFLICT (id) DO NOTHING, so editing the
-- seed alone fixes only fresh installs. On already-seeded clusters the
-- self-referential parent_id made AuthzPartitionSyncEvent write a
-- degenerate self-referential Keto subject-set
-- (tenancy_access:t/p#service <- tenancy_access:t/p#service), so platform
-- service accounts never inherit access and every login on the staging
-- Thesa Studio client fails with:
--   permission_denied: service-authentication cannot service on
--   tenancy_access:d8gueekpf2tfslum7lmg/d8gueekpf2tfslum7ln0
--
-- Idempotent: no-op once parent_id points at the root partition.
-- The hourly synchronize-partitions job (or POST /_system/sync/clients)
-- rewrites the inheritance tuples from the corrected parent_id.

UPDATE partitions
SET parent_id = 'c2f4j7au6s7f91uqnokg',
    modified_at = NOW()
WHERE id = 'd8gueekpf2tfslum7ln0'
  AND parent_id = 'd8gueekpf2tfslum7ln0';
