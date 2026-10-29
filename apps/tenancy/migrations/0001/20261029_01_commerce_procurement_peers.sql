-- Copyright 2023-2026 Ant Investor Ltd
-- Commerce and procurement peer audiences + grants (2026-10-29).
--
-- service_commerce pays refunds out through payment with its own token
-- (Send, then Status and Search to follow the payout), so it needs the
-- /payment audience and payment_send, payment_status_view and payment_search
-- in service_payment. The storefront finds a guest buyer's profile by contact
-- and creates one when none exists (profile Create: profile_create); it
-- already holds profile_view on service_profile.
--
-- service_procurement pushes received resale stock to commerce
-- (ReceiveStock: stock_receive in service_commerce) and books received raw
-- materials into manufacturing inventory (RecordStockIn: inventory_manage in
-- service_manufacturing, where it already holds plan_view). Its setup job
-- registers the stock delivery retry workflow in trustage (Create, Activate,
-- List and Archive workflows: workflow_manage, workflow_view).
--
-- trustage fires that workflow: GoodsReceiptDeliver (goods_receipt_deliver in
-- service_procurement) with the /procurement audience.

-- service_commerce → service_payment, service_profile
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbhph2cpf2t1iig5ksf0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33eg', 'https://api.stawi.org/payment') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbhph2cpf2t1iig5ksfg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e33g0', 'service_payment', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5ksg0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksfg', 'payment_send') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5ksgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksfg', 'payment_status_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5ksh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksfg', 'payment_search') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5kshg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dau0j24pf2t3vfe1ohrg', 'profile_create') ON CONFLICT (id) DO NOTHING;

-- service_procurement → service_commerce, service_trustage, service_manufacturing
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbhph2cpf2t1iig5ksi0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e3410', 'https://api.stawi.org/commerce') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbhph2cpf2t1iig5ksig', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e3410', 'https://api.stawi.org/trustage') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbhph2cpf2t1iig5ksj0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e342g', 'service_commerce', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbhph2cpf2t1iig5ksjg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'daeltdcpf2t6p29e342g', 'service_trustage', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5ksk0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksj0', 'stock_receive') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5kskg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksjg', 'workflow_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5ksl0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksjg', 'workflow_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5kslg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbas5dcpf2t4oekfdkh0', 'inventory_manage') ON CONFLICT (id) DO NOTHING;

-- trustage → service_procurement
INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('dbhph2cpf2t1iig5ksm0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnplg', 'https://api.stawi.org/procurement') ON CONFLICT (client_ref, resource_audience) DO NOTHING;
INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('dbhph2cpf2t1iig5ksmg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp1f0', 'service_procurement', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbhph2cpf2t1iig5ksn0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbhph2cpf2t1iig5ksmg', 'goods_receipt_deliver') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump each policy's generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('daeltdcpf2t6p29e33g0', 'daeltdcpf2t6p29e342g', 'd94lkmcpf2t39vdkp1f0');

-- Re-sync the Hydra clients so the new audiences land in their allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id IN ('service-commerce', 'service-procurement', 'trustage');
