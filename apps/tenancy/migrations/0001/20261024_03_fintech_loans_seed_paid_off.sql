-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech loans -> seed paid-off hook (2026-10-24).
--
-- When a loan is repaid in full the loans service calls seed's
-- LoanPaidOffNotify so seed completes its loan request and credits the
-- borrower's profile. The loans client needs the /seed audience and
-- seed_loan_paid_off_notify on service_seed.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbef8dspf2te3pa5p98g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnpvg', 'https://api.stawi.org/seed') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbef8dspf2te3pa5p990', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp420', 'service_seed', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbef8dspf2te3pa5p99g', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbef8dspf2te3pa5p990', 'seed_loan_paid_off_notify') ON CONFLICT (id) DO NOTHING;
