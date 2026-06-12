-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: promote the platform operator (profile d75qclkpf2t1uum8ij3g)
-- from member to owner on the root partition and the Thesa Development
-- staging partition.
--
-- The operator was the sole access record on the root partition but held
-- only the `member` role, so:
--   * EnsureRootAuthorization found no root owner/admin and always skipped,
--     leaving the "internal" super-user tuples unwritten;
--   * every write/admin action in the Thesa admin console (send
--     notification, manage settings, grant access, …) was denied because
--     member binds to read-only permissions in each service's OPL.
-- The admin console operator must be an owner for the console to function.
--
-- Idempotent: re-points the existing access_roles rows at the owner
-- partition_role; no-op once already owner. Clearing the accesses'
-- modified_at re-queues them for Keto role-tuple sync.

-- Root partition (c2f4j7au6s7f91uqnokg): member -> owner
UPDATE access_roles
SET partition_role_id = 'c2f4j7au6s7f91uqnol0'
WHERE access_id IN (
  SELECT id FROM accesses
  WHERE profile_id = 'd75qclkpf2t1uum8ij3g' AND partition_id = 'c2f4j7au6s7f91uqnokg'
)
AND partition_role_id = 'd7j42dspf2tfev9jfgtg';

-- Thesa Development partition (d8gueekpf2tfslum7ln0): member -> owner
UPDATE access_roles
SET partition_role_id = 'd8gueekpf2tfslum7lng'
WHERE access_id IN (
  SELECT id FROM accesses
  WHERE profile_id = 'd75qclkpf2t1uum8ij3g' AND partition_id = 'd8gueekpf2tfslum7ln0'
)
AND partition_role_id = 'd8gueekpf2tfslum7log';

UPDATE accesses
SET modified_at = NOW()
WHERE profile_id = 'd75qclkpf2t1uum8ij3g'
  AND partition_id IN ('c2f4j7au6s7f91uqnokg', 'd8gueekpf2tfslum7ln0');
