# Ops: service-payment-flutterwave authz repair

## Symptoms
- pay.stawi.org confirm spinner stays on `{"status":"processing"}`
- Flutterwave sandbox charge `status=succeeded`
- `payment-flutterwave` logs: `could not update status` with either
  - Hydra `invalid_client` (missing `service-payment-flutterwave` client), or
  - Keto `permission_denied: … cannot payment_status_update`

## Durable fix
Migration `apps/tenancy/migrations/0001/20260929_01_service_payment_flutterwave.sql`
seeds the client, service account, oauth recipients and the partition_tree
authorization policy (same contract as `service-payment-stripe` /
`service-payment-pawapay`). It resolves rows by `client_id`, so it also repairs a
hand-created client/SA row, and re-queues an already-applied policy.

After merge:
1. Run the tenancy migrate job (`identity-tenancy-migrate`).
2. Run tenancy setup (or `POST /_internal/sync/clients`) so the Hydra client is
   re-synced and the pending SA policy is reconciled into Keto.

## Emergency Keto materialisation (if migrate cannot run)
Clone the stripe bot subject tuples onto the flutterwave bot profile
`d9flwbotprof00000001`. Prefer migration + `ReconcilePending` so partition_tree
grants stay in sync with the policy rows.

## Hydra client metadata (required for private_key_jwt enrichment)
Written by the tenancy client sync from the tenancy rows; verify after setup:
```json
{
  "type": "internal",
  "tenant_id": "c2f4j7au6s7f91uqnojg",
  "partition_id": "c2f4j7au6s7f91uqnokg",
  "profile_id": "d9flwbotprof00000001",
  "service_account_id": "<service_accounts.id for client_id service-payment-flutterwave>"
}
```
On a greenfield database `service_account_id` is `datmso4pf2t98sc6rovg`.

## Bot profile
Profile service: `d9flwbotprof00000001` (`profile_types.uid=2` bot). This id was
hand-assigned in the profile service and is not an rs/xid; tenancy treats it as a
resolved profile (20 chars, no underscore) so `resolveBotProfiles` leaves it alone.
