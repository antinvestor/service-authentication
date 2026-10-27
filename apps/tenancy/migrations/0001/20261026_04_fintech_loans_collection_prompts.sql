-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech loans: collection prompts (2026-10-26).
--
-- service-fintech loans asks a borrower to pay by raising a payment prompt on
-- their own verified mobile number (PaymentService.InitiatePrompt,
-- prompt_initiate). The payment that answers it reaches the loan through the
-- payment rail and operations.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbffmjspf2tcuu2nqo30', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnpvg', 'https://api.stawi.org/payment') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbffmjspf2tcv7bpnj00', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp420', 'service_payment', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbffmjspf2tcvh5g31gg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbffmjspf2tcv7bpnj00', 'prompt_initiate') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy's generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp420';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-loans';
