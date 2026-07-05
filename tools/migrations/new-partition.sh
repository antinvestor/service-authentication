#!/usr/bin/env bash
# tools/migrations/new-partition.sh
# Scaffold a new tenant seed migration under apps/tenancy/migrations/0001/
#
# Usage: NAME=<snake_name> PARENT=<parent partition xid or ROOT> \
#        DISPLAY_NAME=<"Display Name"> DESCRIPTION=<"One line."> \
#        ENVIRONMENT=production RECIPIENTS=<json-array> \
#        REDIRECTS=<json> POST_LOGOUT=<json> LOGO=<url> \
#        CLIENT_NAME=<"Client Name"> \
#        SUPPORT_MSISDN=<phone> SUPPORT_EMAIL=<email> \
#        ./tools/migrations/new-partition.sh

set -euo pipefail

: "${NAME:?NAME required}"
: "${DISPLAY_NAME:?DISPLAY_NAME required}"
: "${DESCRIPTION:?DESCRIPTION required}"
: "${ENVIRONMENT:?ENVIRONMENT required (production|development)}"
: "${RECIPIENTS:?RECIPIENTS JSON array required}"
: "${REDIRECTS:?REDIRECTS JSON required}"
: "${POST_LOGOUT:?POST_LOGOUT JSON required}"
: "${LOGO:?LOGO URL required}"
: "${CLIENT_NAME:?CLIENT_NAME required}"
: "${SUPPORT_MSISDN:?SUPPORT_MSISDN required}"
: "${SUPPORT_EMAIL:?SUPPORT_EMAIL required}"

PARENT="${PARENT:-ROOT}"
DATE=$(date +%Y%m%d)
OUT="apps/tenancy/migrations/0001/${DATE}_partition_${NAME}.sql"
TEMPLATE="apps/tenancy/migrations/templates/partition.template"

if [ ! -f "$TEMPLATE" ]; then
  echo "missing template: $TEMPLATE" >&2
  exit 1
fi
if [ -f "$OUT" ]; then
  echo "migration already exists: $OUT" >&2
  exit 1
fi

# Generate 7 xids: tenant, partition, 3 roles, 1 client, 1 client_id.
mapfile -t XIDS < <(go run ./tools/xid --count 7)
TENANT="${XIDS[0]}"
PARTITION="${XIDS[1]}"
ROLE_OWNER="${XIDS[2]}"
ROLE_ADMIN="${XIDS[3]}"
ROLE_MEMBER="${XIDS[4]}"
CLIENT="${XIDS[5]}"
CLIENT_ID="${XIDS[6]}"

if [ "$PARENT" = "ROOT" ]; then
  PARENT_XID="$PARTITION"
else
  PARENT_XID="$PARENT"
fi

esc() { printf '%s' "$1" | sed "s/'/''/g"; }

sed \
  -e "s/__DISPLAY_NAME__/$(esc "$DISPLAY_NAME")/g" \
  -e "s/__DESCRIPTION__/$(esc "$DESCRIPTION")/g" \
  -e "s/__ENVIRONMENT__/$(esc "$ENVIRONMENT")/g" \
  -e "s/__TENANT_XID__/$TENANT/g" \
  -e "s/__PARTITION_XID__/$PARTITION/g" \
  -e "s/__PARENT_PARTITION_XID__/$PARENT_XID/g" \
  -e "s/__ROLE_OWNER_XID__/$ROLE_OWNER/g" \
  -e "s/__ROLE_ADMIN_XID__/$ROLE_ADMIN/g" \
  -e "s/__ROLE_MEMBER_XID__/$ROLE_MEMBER/g" \
  -e "s/__CLIENT_XID__/$CLIENT/g" \
  -e "s/__CLIENT_ID_XID__/$CLIENT_ID/g" \
  -e "s/__CLIENT_NAME__/$(esc "$CLIENT_NAME")/g" \
  -e "s|__REDIRECT_URIS_JSON__|$(esc "$REDIRECTS")|g" \
  -e "s|__POST_LOGOUT_URIS_JSON__|$(esc "$POST_LOGOUT")|g" \
  -e "s|__LOGO_URI__|$(esc "$LOGO")|g" \
  -e "s/__SUPPORT_MSISDN__/$(esc "$SUPPORT_MSISDN")/g" \
  -e "s/__SUPPORT_EMAIL__/$(esc "$SUPPORT_EMAIL")/g" \
  "$TEMPLATE" > "$OUT"

go run ./tools/migrations/render-auth-contract \
  --client-id "$CLIENT" \
  --tenant-id "$TENANT" \
  --partition-id "$PARTITION" \
  --recipients "$RECIPIENTS" >> "$OUT"

REG="apps/tenancy/migrations/IDS.md"
python3 - "$REG" "$TENANT" "$PARTITION" "$PARENT_XID" "$CLIENT" "$CLIENT_ID" \
  "$ROLE_OWNER" "$ROLE_ADMIN" "$ROLE_MEMBER" "$NAME" "$DISPLAY_NAME" "$OUT" <<'PY'
import sys, re, pathlib
reg, tenant, partition, parent, client, client_id, ro, ra, rm, name, disp, outfile = sys.argv[1:]
p = pathlib.Path(reg)
src = p.read_text()

def add(section, row):
    global src
    pat = re.compile(r"(## " + re.escape(section) + r"\n\|.*\n\|[-\s|]+\n)")
    src = pat.sub(lambda m: m.group(0) + row + "\n", src, count=1)

add("Tenants",       f"| {tenant} | {disp} | {outfile} |")
add("Partitions",    f"| {partition} | {tenant} | {parent} | {outfile} |")
add("Clients (OAuth2)", f"| {client} | {client_id} | {partition} | {outfile} |")
add("Partition roles",  f"| {ro} | owner  | {partition} | {outfile} |")
add("Partition roles",  f"| {ra} | admin  | {partition} | {outfile} |")
add("Partition roles",  f"| {rm} | member | {partition} | {outfile} |")
p.write_text(src)
PY

echo "created $OUT"
echo "xids appended to $REG"
