-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech operations: investors' capital arrives from the rail (2026-10-26).
--
-- service-fintech funding no longer lets a person record an investor
-- deposit. Operations matches an investor's own payment quoting their
-- investor account (InvestorAccountGet, investor_account_view) and records it
-- with funding (InvestorDeposit, investor_account_manage).

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbfhisspf2t77qnlnff0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnq7g', 'https://api.stawi.org/funding') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbfhisspf2t783h0vc00', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp8i0', 'service_funding', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfhisspf2t78d60q9g0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfhisspf2t783h0vc00', 'investor_account_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbfhisspf2t78mc48e00', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbfhisspf2t783h0vc00', 'investor_account_manage') ON CONFLICT (id) DO NOTHING;

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
