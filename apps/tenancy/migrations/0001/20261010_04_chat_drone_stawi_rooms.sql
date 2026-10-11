-- Copyright 2023-2026 Ant Investor Ltd
-- Service account: service_chat_drone — Stawi rooms relay (stawilabs/chat feat/stawi-rooms).
-- The chat drone relays members' room acts to settlement's RoomService
-- (PrepareRoomGenesis, SubmitRoomGenesisSignature, PrepareRoomCall,
-- SubmitRoomCall: room_manage; GetRoomGenesis, GetRoomCall: room_view in
-- namespace service_settlement) and maps chain addresses to profiles through
-- profile's ResolveAccounts (account_resolve, added to the drone's existing
-- service_profile grant). The token needs the /stawi-settlement audience.

INSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES ('db5iu7cpf2t21sa27qgg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'c2f4j7au6s7f91uqnpdg', 'https://api.stawi.org/stawi-settlement') ON CONFLICT (client_ref, resource_audience) DO NOTHING;

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu7cpf2t21sa27qh0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp0d0', 'account_resolve') ON CONFLICT (id) DO NOTHING;

INSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES ('db5iu7cpf2t21sa27qhg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'd94lkmcpf2t39vdkp050', 'service_settlement', 'partition_tree') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu7cpf2t21sa27qi0', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu7cpf2t21sa27qhg', 'room_manage') ON CONFLICT (id) DO NOTHING;
INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('db5iu7cpf2t225dtlbsg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'db5iu7cpf2t21sa27qhg', 'room_view') ON CONFLICT (id) DO NOTHING;

-- New desired state → bump the policy generation so the reconciler re-applies it.
UPDATE service_account_authorization_policies
SET generation = generation + 1,
    status = 'pending',
    retry_count = 0,
    next_attempt_at = NULL,
    last_error = NULL,
    modified_at = NOW()
WHERE id = 'd94lkmcpf2t39vdkp050';

-- Re-sync the Hydra client so the new audience lands in its allowed audiences.
UPDATE public.clients
SET modified_at = NOW(),
    synced_at = NULL
WHERE client_id = 'service-chat-drone';
