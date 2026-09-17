#!/usr/bin/env bash
# apply-firewall.sh - bootstrap the SOC auto-block alias on pfSense and
# reload the filter, so soc-lite has a target to enforce against.
#
# Idempotent: safe to re-run. Requires the pfSense REST API package
# (github.com/jaredhendrickson13/pfsense-api) and an API token from
# System > User Manager > API.
#
# Usage:
#   export PF_HOST="https://192.168.1.1"
#   export PF_TOKEN="<api token>"
#   bash firewall/apply-firewall.sh
set -euo pipefail

: "${PF_HOST:?export PF_HOST (e.g. https://192.168.1.1)}"
: "${PF_TOKEN:?export PF_TOKEN (pfSense user api token)}"

ALIAS_NAME="${ALIAS_NAME:-SOC_AUTO_BLOCK}"
RESP="$(mktemp)"
trap 'rm -f "$RESP"' EXIT

CODE="$(curl -sk -o "$RESP" -w '%{http_code}' -X POST \
  "$PF_HOST/api/v1/firewall/alias" \
  -H "Authorization: $PF_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$ALIAS_NAME\",\"type\":\"host\",\"descr\":\"soc-lite auto block list (managed)\",\"address\":\"\"}")"

if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
  echo "[+] alias $ALIAS_NAME created"
elif [[ "$CODE" == "400" ]]; then
  echo "[i] alias $ALIAS_NAME probably already exists (HTTP 400), continuing"
else
  echo "[!] alias bootstrap returned HTTP $CODE" >&2
  cat "$RESP" >&2
  exit 1
fi

CODE="$(curl -sk -o "$RESP" -w '%{http_code}' -X POST \
  "$PF_HOST/api/v1/firewall/apply" -H "Authorization: $PF_TOKEN")"

if [[ "$CODE" != "200" ]]; then
  echo "[!] filter apply returned HTTP $CODE" >&2
  cat "$RESP" >&2
  exit 1
fi

echo "[+] filter reloaded - soc-lite can enforce blocks now"
