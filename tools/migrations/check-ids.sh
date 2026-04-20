#!/usr/bin/env bash
# tools/migrations/check-ids.sh — verifies every xid referenced in
# apps/tenancy/migrations/0001/*.sql appears in IDS.md, and vice versa.
# Fails non-zero if any SQL xid is not registered.

set -euo pipefail
DIR="apps/tenancy/migrations/0001"
REG="apps/tenancy/migrations/IDS.md"

# xids look like 20-char [0-9a-v] strings (rs/xid alphabet).
PATTERN="[0-9a-v]{20}"

sql_ids=$(grep -hoE "'${PATTERN}'" "$DIR"/*.sql 2>/dev/null \
  | tr -d "'" | sort -u || true)
reg_ids=$(grep -hoE "${PATTERN}" "$REG" 2>/dev/null | sort -u || true)

missing_from_registry=$(comm -23 <(echo "$sql_ids") <(echo "$reg_ids") || true)
missing_from_sql=$(comm -13 <(echo "$sql_ids") <(echo "$reg_ids") || true)

status=0
if [ -n "$missing_from_registry" ]; then
  echo "ERROR: xids in SQL not registered in IDS.md:" >&2
  echo "$missing_from_registry" >&2
  status=1
fi
if [ -n "$missing_from_sql" ]; then
  echo "WARN: xids in IDS.md not referenced in any SQL (stale):" >&2
  echo "$missing_from_sql" >&2
  # WARN only — does not fail.
fi

exit $status
