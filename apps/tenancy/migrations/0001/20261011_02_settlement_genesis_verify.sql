-- Copyright 2023-2026 Ant Investor Ltd
-- service_settlement → authentication.v1 VerifyGenesisSessionProof (2026-10-11).
-- Verify with consume spends a person's genesis session proof, so it needs
-- auth_genesis_verify in namespace service_authentication. No role carries
-- that permission; settlement, the consumer that acts on the proof in
-- DeployAccount, is the only principal granted it.

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5li0kpf2t2i2o15i5g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu14pf2t15n40lj3g', 'service_authentication', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5li0kpf2t2i2o15i60', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5li0kpf2t2i2o15i5g', 'auth_genesis_verify') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'db5iu14pf2t15n40lj3g';
