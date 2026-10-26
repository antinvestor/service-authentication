-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech loans: staff roles no longer hold repayment_manage (2026-10-26).
--
-- Borrowers repay from their own contact; a repayment is recorded only by the
-- payment rail (service-fintech v1.96.42), so service_loans dropped
-- repayment_manage from the owner, admin, operator and member role bindings
-- and the OPL no longer grants it through those roles. Manifest registration
-- keeps role bindings additive-only and refused the new manifest with 409,
-- so the stored bindings are narrowed here to match. The generation bump
-- makes the next registration reconcile. The guard keeps a re-run a no-op.

UPDATE service_namespaces
SET role_bindings = jsonb_set(
        jsonb_set(
            jsonb_set(
                jsonb_set(role_bindings, '{owner}', (role_bindings -> 'owner') - 'repayment_manage'),
                '{admin}', (role_bindings -> 'admin') - 'repayment_manage'),
            '{operator}', (role_bindings -> 'operator') - 'repayment_manage'),
        '{member}', (role_bindings -> 'member') - 'repayment_manage'),
    generation = generation + 1,
    modified_at = CURRENT_TIMESTAMP
WHERE namespace = 'service_loans'
  AND (role_bindings -> 'owner' ? 'repayment_manage'
       OR role_bindings -> 'admin' ? 'repayment_manage'
       OR role_bindings -> 'operator' ? 'repayment_manage'
       OR role_bindings -> 'member' ? 'repayment_manage');
