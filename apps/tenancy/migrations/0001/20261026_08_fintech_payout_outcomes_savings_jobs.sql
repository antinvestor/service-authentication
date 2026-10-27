-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech: payouts the rail fails after accepting them, and savings interest
-- on the platform scheduler (2026-10-26).
--
-- service-fintech operations now asks the payment service how each payout
-- ended (OperationsJobRun RECONCILE_PAYOUTS, on the existing trustage
-- grant). A payout the rail failed after accepting it is reversed on the
-- ledger, and operations tells the service that raised it, which undoes its
-- own record: PayoutFailedApply (payout_outcome_apply) on loans
-- (disbursements, team commission payouts), savings (withdrawals) and
-- funding (investor withdrawals).
--
-- Savings no longer accrues interest on an in-process timer: trustage fires
-- SavingsJobRun (savings_job_run), and the savings setup job registers the
-- schedule (workflow_manage, workflow_view on service_trustage).

-- service_operations → loans, savings, funding: payout_outcome_apply
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfmdg4pf2t0lej3em80', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etf0', 'payout_outcome_apply') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfmdg4pf2t0lntssre0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbff1gcpf2tatgbhhqv0', 'payout_outcome_apply') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfmdg4pf2t0m1d5ojs0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfhisspf2t783h0vc00', 'payout_outcome_apply') ON CONFLICT (id) DO NOTHING;

-- service_savings → trustage
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfmdgcpf2t0mat1o3e0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq5g', 'https://api.stawi.org/trustage') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfmdgcpf2t0mkdd3nt0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp7f0', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfmdgcpf2t0mthrbsug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfmdgcpf2t0mkdd3nt0', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfmdgcpf2t0n6qlfu3g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfmdgcpf2t0mkdd3nt0', 'workflow_view') ON CONFLICT (id) DO NOTHING;

-- trustage → service_savings
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfmdgcpf2t0ngaff920', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/savings') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfmdgcpf2t0npt78r6g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_savings', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfmdgcpf2t0o32c1eqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfmdgcpf2t0npt78r6g', 'savings_job_run') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('d94lkmcpf2t39vdkp8i0', 'd94lkmcpf2t39vdkp7f0', 'd94lkmcpf2t39vdkp1f0');

-- Re-sync the Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-savings', 'trustage');
