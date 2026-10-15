-- Copyright 2023-2026 Ant Investor Ltd
-- Stawi loan book release grants (stawi v0.2.0, chat v1.0.26; 2026-10-15).
--
-- 1. Finance puts a personal loan's cards into its people's own DM or Stawi
--    notices room. It finds or creates that room through chat's CreateRoom
--    (room_create), which answers a service principal holding
--    stawi_room_resolve with the people's own room, and checks the room and
--    its members (room_view, subscription_view). All in service_chat, added to
--    finance's existing service_chat grant (20261011_03). Same set as the
--    stawilabs/stawi stack test (stacktest/platform/keto.go ServiceGrants).
--
-- 2. Finance reads settlement's RoomService (GetChainHead, ListMemberBooks,
--    GetRoomEngines, GetLoanSchedule, GetMemberDues): room_view in
--    service_settlement, added to finance's existing service_settlement grant.
--
-- 3. Chat answers GetDirectPartnerAccount through settlement's
--    AccountService.GetProfileAccount: profile_account_view in
--    service_settlement, added to chat's existing service_settlement grant
--    (20261010_04).
--
-- A grant naming a permission the namespace has not registered yet fails its
-- policy until the owning service's setup job registers it; registration
-- re-queues every policy that grants the namespace.

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db8ag34pf2t6oeanubb0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvss0', 'stawi_room_resolve') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db8ag34pf2t6oeanubbg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvss0', 'room_create') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db8ag34pf2t6oeanubc0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvss0', 'room_view') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db8ag34pf2t6oeanubcg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5luv4pf2t0o1dkvss0', 'subscription_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db8ag34pf2t6oeanubd0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu0spf2t14odh5bg0', 'room_view') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db8ag34pf2t6oeanubdg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu7cpf2t21sa27qhg', 'profile_account_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump both policies' generation so the reconciler re-applies them.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id IN ('db5itnspf2tft2pp30f0', 'd94lkmcpf2t39vdkp050');
