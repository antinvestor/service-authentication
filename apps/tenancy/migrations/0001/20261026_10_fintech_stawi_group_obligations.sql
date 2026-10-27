-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech stawi: group obligations live in operations (2026-10-26).
--
-- service-fintech stawi no longer runs its own copy of the operations code.
-- It raises each period's member savings obligations and closes periods
-- through operations' GroupObligationsRaise and GroupPeriodClose
-- (group_obligation_manage, service accounts only), and operations applies
-- members' suspense and allocates their payments itself. Stawi's manifest
-- therefore dropped stawi_obligation_view, stawi_payment_view and
-- stawi_payment_allocate; the stored namespace is narrowed to match so the
-- additive-only registration accepts it.

-- service_stawi → operations: group_obligation_manage (on its existing grant)
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfqh0kpf2t117mdcoe0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkpd10', 'group_obligation_manage') ON CONFLICT (id) DO NOTHING;

UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkpbk0';

UPDATE service_namespaces
SET permissions = jsonb_set(permissions, '{values}',
        (permissions -> 'values') - ARRAY['stawi_obligation_view', 'stawi_payment_view', 'stawi_payment_allocate']),
    role_bindings = (
        SELECT COALESCE(jsonb_object_agg(role, perms - ARRAY['stawi_obligation_view', 'stawi_payment_view',
                                                           'stawi_payment_allocate']), '{}'::jsonb)
        FROM jsonb_each(role_bindings) AS rb(role, perms)
    ),
    generation = generation + 1,
    modified_at = CURRENT_TIMESTAMP
WHERE namespace = 'service_stawi'
  AND (permissions -> 'values') ?| ARRAY['stawi_obligation_view', 'stawi_payment_view', 'stawi_payment_allocate'];
