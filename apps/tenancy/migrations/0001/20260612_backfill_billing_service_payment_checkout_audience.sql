-- Copyright 2023-2026 Ant Investor Ltd
-- Backfill: add the `service_payment_checkout` audience to the
-- service-billing client + service_account so billing can create and
-- verify hosted checkout sessions for invoices
-- (antinvestor/service-payment checkout integration).

UPDATE clients
SET audiences = audiences || '{"service_payment_checkout":["*"]}'::jsonb,
    synced_at = NULL
WHERE id = 'c2f4j7au6s7f91uqnp9g'
  AND NOT (audiences ? 'service_payment_checkout');

UPDATE service_accounts
SET audiences = audiences || '{"service_payment_checkout":["*"]}'::jsonb
WHERE id = 'c2f4j7au6s7f91uqnpag'
  AND NOT (audiences ? 'service_payment_checkout');
