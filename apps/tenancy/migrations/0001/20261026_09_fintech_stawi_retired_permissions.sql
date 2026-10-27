-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech stawi: retired group payment and loan origination flows (2026-10-26).
--
-- service-fintech stawi no longer routes group payments, moves ledger money,
-- sources funding or generates, funds and disburses loan offers itself:
-- operations receives payments and loans originates and funds loans. Its
-- manifest dropped stawi_loan_offer_manage, stawi_loan_view, stawi_loan_fund,
-- stawi_loan_disburse and stawi_ledger_transfer. Registration keeps
-- permissions and role bindings additive-only and would refuse the new
-- manifest with 409, so the stored namespace is narrowed here to match. The
-- generation bump makes the next registration reconcile; the guard keeps a
-- re-run a no-op.

UPDATE service_namespaces
SET permissions = jsonb_set(permissions, '{values}',
        (permissions -> 'values') - ARRAY['stawi_loan_offer_manage', 'stawi_loan_view', 'stawi_loan_fund',
                                          'stawi_loan_disburse', 'stawi_ledger_transfer']),
    role_bindings = (
        SELECT COALESCE(jsonb_object_agg(role, perms - ARRAY['stawi_loan_offer_manage', 'stawi_loan_view',
                                                           'stawi_loan_fund', 'stawi_loan_disburse',
                                                           'stawi_ledger_transfer']), '{}'::jsonb)
        FROM jsonb_each(role_bindings) AS rb(role, perms)
    ),
    generation = generation + 1,
    modified_at = CURRENT_TIMESTAMP
WHERE namespace = 'service_stawi'
  AND (permissions -> 'values') ?| ARRAY['stawi_loan_offer_manage', 'stawi_loan_view', 'stawi_loan_fund',
                                        'stawi_loan_disburse', 'stawi_ledger_transfer'];
