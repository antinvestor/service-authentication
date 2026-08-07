# Ops: service-payment-flutterwave authz repair

## Symptoms
- pay.stawi.org confirm spinner stays on `{"status":"processing"}`
- Flutterwave sandbox charge `status=succeeded`
- `payment-flutterwave` logs: `could not update status` with either
  - Hydra `invalid_client` (missing `service-payment-flutterwave` client), or
  - Keto `permission_denied: … cannot payment_status_update`

## Durable fix
Migration `apps/tenancy/migrations/0001/20260807_01_service_payment_flutterwave.sql`
plus tenancy migrate + SA policy reconcile (setup job or `/_internal/sync/clients`).

## Emergency Keto materialisation (if migrate cannot run)
Clone stripe bot subject tuples onto flutterwave bot profile
`d9flwbotprof00000001` (see prior incident notes). Prefer migration +
`ReconcilePending` so partition_tree stays in sync with policy rows.

## Hydra client metadata (required for private_key_jwt enrichment)
```json
{
  "type": "internal",
  "tenant_id": "c2f4j7au6s7f91uqnojg",
  "partition_id": "c2f4j7au6s7f91uqnokg",
  "profile_id": "d9flwbotprof00000001",
  "service_account_id": "<service_accounts.id for client_id service-payment-flutterwave>"
}
```

## Bot profile
Profile service: `d9flwbotprof00000001` (`profile_types.uid=2` bot).
