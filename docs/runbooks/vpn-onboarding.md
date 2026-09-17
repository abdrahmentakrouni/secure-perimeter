# Runbook: VPN Onboarding (Telework / Branch Office)

Two minutes per worker, no pfSense GUI required. Everything below runs
on the admin workstation with wireguard-tools installed.

## One-time environment

```bash
export PF_HOST="https://192.168.1.1"
export PF_TOKEN="<api token for soc-lite user>"
export PF_WG_ENDPOINT="vpn.corp.example.tn:51820"
export PF_WG_PUBKEY="<server public key from VPN > WireGuard>"
```

## Onboard

```bash
bash vpn/provision-peer.sh analyst-01
# [+] peer analyst-01 provisioned
#     client ip : 10.99.1.10
#     pubkey    : <client public key>
#     profile   : vpn/peers/analyst-01.conf (permissions 600)
#     register  : peer registered on edge-fw01 via pfSense API
```

Send the generated profile (or let the new hire scan the QR from the
screen) over a channel that is not email. The private key never leaves
the admin box except inside that profile.

What the worker gets: an address in the 10.99.0.0/22 pool and a
split-tunnel profile - only 10.20.20.0/24 (the DMZ apps) rides the
tunnel, internet traffic stays local, and the firewall's VPN-to-LAN
deny rule closes the rest. Least privilege by design.

## Verify

- `wg show` on the client shows a latest handshake within seconds.
- `curl -m 3 https://10.20.20.10:8443/healthz` works through the tunnel.
- `curl -m 3 http://10.10.10.5/` times out (VPN-to-LAN is denied and
  logged - by design).

## Revoke

```bash
bash vpn/revoke-peer.sh analyst-01
# [+] peer analyst-01 revoked (10.99.1.10)
```

The peer disappears from the firewall (API), the local profile is
archived with a timestamp, and the revocation is appended to
`peers/revocations.tsv`. Do this the same day HR says goodbye, not the
same week (threat T11 in the threat model).

## Branch office variant

A site with a fixed public IP can ride the same tunnel type: provision
a peer named after the site (`bash vpn/provision-peer.sh site-bizerte`),
then put the generated key material into the office router's WireGuard
client mode with `AllowedIPs = 10.20.20.0/24` in reverse. IKEv2/IPsec
phase1/phase2 parameters for sites that only speak IPsec: AES-256-GCM,
SHA-256, DH group 19 (ECP256), IKEv2, PFS on, DPD 30 s.
