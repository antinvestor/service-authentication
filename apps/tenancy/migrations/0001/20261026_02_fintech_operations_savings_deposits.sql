-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech operations: deposit savers' mobile money (2026-10-26).
--
-- service-fintech operations now matches a saver's incoming mobile-money
-- payment to their own savings account, and staff may assign an unmatched
-- payment to one. Operations records the deposit with the savings service
-- (DepositRecord, deposit_manage) after reading the account
-- (SavingsAccountGet/Search, savings_account_view). The savings service now
-- refuses deposits from anyone but an internal caller, so nobody types a
-- deposit amount.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbff1gcpf2tat6q49fqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq7g', 'https://api.stawi.org/savings') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbff1gcpf2tatgbhhqv0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp8i0', 'service_savings', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbff1gcpf2tatpv26bug', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbff1gcpf2tatgbhhqv0', 'savings_account_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbff1gkpf2tau33alsr0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbff1gcpf2tatgbhhqv0', 'deposit_manage') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy's generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp8i0';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-operations';
