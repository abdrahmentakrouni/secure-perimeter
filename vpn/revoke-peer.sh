#!/usr/bin/env bash
# revoke-peer.sh - remove a teleworker from the perimeter.
#
# Best effort through the pfSense REST API when PF_HOST/PF_TOKEN are
# exported; always archives the local profile and records the revocation.
#
# Usage:
#   bash vpn/revoke-peer.sh analyst-01
set -euo pipefail

NAME="${1:-}"
if [[ -z "$NAME" ]]; then
  echo "usage: revoke-peer.sh <name>" >&2
  exit 64
fi

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
CONF="$BASEDIR/peers/$NAME.conf"
ALLOC="$BASEDIR/peers/allocations.tsv"
REVO="$BASEDIR/peers/revocations.tsv"

if ! [[ -f "$ALLOC" ]] || ! awk -F'\t' -v n="$NAME" \
    '$1 == n { found=1 } END { exit !found }' "$ALLOC"; then
  echo "error: peer '$NAME' not found in peers/allocations.tsv" >&2
  exit 66
fi

IP="$(awk -F'\t' -v n="$NAME" '$1 == n { print $2; exit }' "$ALLOC")"

API_NOTE="manual removal required (PF_HOST/PF_TOKEN not set)"
if [[ -n "${PF_HOST:-}" && -n "${PF_TOKEN:-}" ]]; then
  RESP="$(mktemp)"
  trap 'rm -f "$RESP"' EXIT
  CODE="$(curl -sk -o "$RESP" -w '%{http_code}' -X DELETE \
    "$PF_HOST/api/v1/wireguard/peer" \
    -H "Authorization: $PF_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"peer_name\":\"$NAME\"}")" || CODE="000"
  if [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
    curl -sk -X POST "$PF_HOST/api/v1/firewall/apply" \
      -H "Authorization: $PF_TOKEN" >/dev/null || true
    API_NOTE="peer removed from edge-fw01 via pfSense API"
  else
    API_NOTE="pfSense API returned HTTP $CODE - remove the peer manually"
  fi
fi

if [[ -f "$CONF" ]]; then
  mv "$CONF" "$CONF.revoked-$(date +%s)"
fi
printf '%s\t%s\t%s\n' "$NAME" "$IP" \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$REVO"

echo "[+] peer $NAME revoked ($IP)"
echo "    register  : $API_NOTE"
echo "    local profile archived, revocation logged to peers/revocations.tsv"
