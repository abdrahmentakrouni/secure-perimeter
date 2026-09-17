#!/usr/bin/env bash
# provision-peer.sh - onboard a teleworker onto the WireGuard perimeter.
#
# Generates the keypair + pre-shared key, renders the client profile and
# (when PF_HOST/PF_TOKEN are exported) registers the peer on pfSense via
# the REST API. Private keys never leave this machine except into the
# client profile itself.
#
# Usage:
#   export PF_WG_ENDPOINT="vpn.corp.example.tn:51820"
#   export PF_WG_PUBKEY="<server public key>"
#   export PF_HOST="https://192.168.1.1"     # optional: enables API push
#   export PF_TOKEN="<api token>"            # optional: enables API push
#   bash vpn/provision-peer.sh analyst-01 [10.99.1.42]
set -euo pipefail

NAME="${1:-}"
CLIENT_IP="${2:-}"

if [[ -z "$NAME" ]]; then
  echo "usage: provision-peer.sh <name> [client_ip]" >&2
  exit 64
fi
if [[ ! "$NAME" =~ ^[a-z0-9][a-z0-9_-]{1,31}$ ]]; then
  echo "error: name must match [a-z0-9][a-z0-9_-]{1,31}" >&2
  exit 64
fi

: "${PF_WG_ENDPOINT:?export PF_WG_ENDPOINT (e.g. vpn.corp.example.tn:51820)}"
: "${PF_WG_PUBKEY:?export PF_WG_PUBKEY (server public key)}"

if ! command -v wg >/dev/null 2>&1; then
  echo "error: wireguard-tools required (wg binary not found)" >&2
  exit 69
fi

BASEDIR="$(cd "$(dirname "$0")" && pwd)"
PEER_DIR="$BASEDIR/peers"
ALLOC="$PEER_DIR/allocations.tsv"
mkdir -p "$PEER_DIR"

if [[ -f "$ALLOC" ]] && awk -F'\t' -v n="$NAME" \
    '$1 == n { found=1 } END { exit !found }' "$ALLOC"; then
  echo "error: peer '$NAME' already provisioned (see peers/allocations.tsv)" >&2
  exit 65
fi

# auto-allocate the next address in the telework pool (10.99.1.10+)
if [[ -z "$CLIENT_IP" ]]; then
  COUNT=0
  if [[ -f "$ALLOC" ]]; then
    COUNT="$(wc -l < "$ALLOC" | tr -d ' ')"
  fi
  CLIENT_IP="10.99.1.$((10 + COUNT))"
fi
if [[ ! "$CLIENT_IP" =~ ^10\.99\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "error: client ip must be inside the 10.99.0.0/22 telework pool" >&2
  exit 64
fi

umask 077
CLIENT_PRIV="$(wg genkey)"
CLIENT_PUB="$(printf '%s' "$CLIENT_PRIV" | wg pubkey)"
PSK="$(wg genpsk)"

CONF="$PEER_DIR/$NAME.conf"
sed \
  -e "s|__CLIENT_PRIVATE_KEY__|$CLIENT_PRIV|" \
  -e "s|__CLIENT_ADDRESS__|$CLIENT_IP|" \
  -e "s|__SERVER_PUBLIC_KEY__|$PF_WG_PUBKEY|" \
  -e "s|__PRESHARED_KEY__|$PSK|" \
  -e "s|__ENDPOINT__|$PF_WG_ENDPOINT|" \
  "$BASEDIR/client-template.conf" > "$CONF"

printf '%s\t%s\t%s\n' "$NAME" "$CLIENT_IP" \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$ALLOC"

API_NOTE="PF_HOST/PF_TOKEN not set - register the peer manually (pubkey below)"
if [[ -n "${PF_HOST:-}" && -n "${PF_TOKEN:-}" ]]; then
  RESP="$(mktemp)"
  trap 'rm -f "$RESP"' EXIT
  CODE="$(curl -sk -o "$RESP" -w '%{http_code}' -X POST \
    "$PF_HOST/api/v1/wireguard/peer" \
    -H "Authorization: $PF_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"peer_name\":\"$NAME\",\"public_key\":\"$CLIENT_PUB\",\"preshared_key\":\"$PSK\",\"allowed_ips\":\"$CLIENT_IP/32\"}")" \
    || CODE="000"
  if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
    curl -sk -X POST "$PF_HOST/api/v1/firewall/apply" \
      -H "Authorization: $PF_TOKEN" >/dev/null || true
    API_NOTE="peer registered on edge-fw01 via pfSense API"
  else
    API_NOTE="pfSense API returned HTTP $CODE - register manually (pubkey below)"
  fi
fi

echo "[+] peer $NAME provisioned"
echo "    client ip : $CLIENT_IP"
echo "    pubkey    : $CLIENT_PUB"
echo "    profile   : $CONF (permissions 600)"
echo "    register  : $API_NOTE"

if command -v qrencode >/dev/null 2>&1; then
  echo "[i] scan with the WireGuard mobile app:"
  qrencode -t ansiutf8 < "$CONF"
fi
