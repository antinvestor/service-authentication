#!/usr/bin/env bash
# tools/migrations/new-service.sh
#
# Usage: NAME=<snake> DESCRIPTION=<"One line."> \
#        TENANT_XID=<xid> PARTITION_XID=<xid> \
#        PROFILE_XID=<placeholder profile xid> \
#        RECIPIENTS=<json-array> GRANTS=<json-object> \
#        ./tools/migrations/new-service.sh
#
# For Thesa-bound SAs, use the root tenant/partition xids.
# For stawi-jobs-bound SAs, use the stawi-jobs tenant/partition xids.

set -euo pipefail

: "${NAME:?NAME required}"
: "${DESCRIPTION:?DESCRIPTION required}"
: "${TENANT_XID:?TENANT_XID required}"
: "${PARTITION_XID:?PARTITION_XID required}"
: "${PROFILE_XID:?PROFILE_XID required (placeholder resolved by resolveBotProfiles at startup)}"
: "${RECIPIENTS:?RECIPIENTS JSON array required}"
: "${GRANTS:?GRANTS JSON object required}"

DATE=$(date +%Y%m%d)
OUT="apps/tenancy/migrations/0001/${DATE}_service_${NAME}.sql"
TEMPLATE="apps/tenancy/migrations/templates/service.template"

if [ ! -f "$TEMPLATE" ]; then
  echo "missing template: $TEMPLATE" >&2
  exit 1
fi
if [ -f "$OUT" ]; then
  echo "migration already exists: $OUT" >&2
  exit 1
fi

mapfile -t XIDS < <(go run ./tools/xid --count 4)
CLIENT="${XIDS[0]}"
CLIENT_ID="${XIDS[1]}"
SERVICE_ACCOUNT="${XIDS[2]}"
POLICY="${XIDS[3]}"

esc() { printf '%s' "$1" | sed "s/'/''/g"; }

sed \
  -e "s/__SA_NAME__/$(esc "$NAME")/g" \
  -e "s/__DESCRIPTION__/$(esc "$DESCRIPTION")/g" \
  -e "s/__TENANT_XID__/$TENANT_XID/g" \
  -e "s/__PARTITION_XID__/$PARTITION_XID/g" \
  -e "s/__CLIENT_XID__/$CLIENT/g" \
  -e "s/__CLIENT_ID_XID__/$CLIENT_ID/g" \
  -e "s/__SERVICE_ACCOUNT_XID__/$SERVICE_ACCOUNT/g" \
  -e "s/__PROFILE_XID__/$PROFILE_XID/g" \
  "$TEMPLATE" > "$OUT"

go run ./tools/migrations/render-auth-contract \
  --client-id "$CLIENT" \
  --tenant-id "$TENANT_XID" \
  --partition-id "$PARTITION_XID" \
  --recipients "$RECIPIENTS" \
  --service-account-id "$SERVICE_ACCOUNT" \
  --policy-id "$POLICY" \
  --grants "$GRANTS" >> "$OUT"

REG="apps/tenancy/migrations/IDS.md"
python3 - "$REG" "$CLIENT" "$CLIENT_ID" "$SERVICE_ACCOUNT" "$PROFILE_XID" "$NAME" "$OUT" <<'PY'
import sys, re, pathlib
reg, client, client_id, sa, profile, name, outfile = sys.argv[1:]
p = pathlib.Path(reg)
src = p.read_text()
def add(section, row):
    global src
    pat = re.compile(r"(## " + re.escape(section) + r"\n\|.*\n\|[-\s|]+\n)")
    src = pat.sub(lambda m: m.group(0) + row + "\n", src, count=1)
add("Clients (OAuth2)",   f"| {client} | {client_id} | (SA: {name}) | {outfile} |")
add("Service accounts",   f"| {sa} | {profile} | {client} | {outfile} |")
p.write_text(src)
PY

echo "created $OUT"
echo "xids appended to $REG"
