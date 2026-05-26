-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add `service_chat_drone` audience to service-chat-gateway.
-- The seed used `service_chat` but the deployment requests
-- `service_chat_drone` which matches chat-drone's verify audience.
--
-- Clearing synced_at forces the next sync cycle to POST the corrected
-- audience list to Hydra.

UPDATE clients
SET audiences = audiences || '{"service_chat_drone":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnpfg'
  AND NOT (audiences ? 'service_chat_drone');

UPDATE service_accounts
SET audiences = audiences || '{"service_chat_drone":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnpgg'
  AND NOT (audiences ? 'service_chat_drone');
