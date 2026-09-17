# Threat Model (STRIDE)

Scope: edge-fw01, the four zones behind it, and the remote workforce
connecting through WireGuard. Assets first, then one row per threat with
the control that answers it.

## Assets

| # | asset | why it matters |
|---|-------|----------------|
| A1 | DMZ application servers (app-01, app-02) | customer-facing business logic |
| A2 | LAN workstations and file shares | staff productivity, internal documents |
| A3 | firewall admin plane (GUI, API token) | total control of the perimeter |
| A4 | telework credentials (private keys, PSK) | identity of the remote workforce |
| A5 | detection history (eve.json, filter logs) | evidence for incident response |

## Threats and controls

| id | stride | threat | control |
|----|--------|--------|---------|
| T1 | Spoofing | attacker forges an internal address to walk in | WAN default deny + pfSense anti-spoof on interface rules; suricata drop on spoofed ranges |
| T2 | Spoofing | stolen or cloned laptop pretends to be a teleworker | WireGuard keypair + per-peer pre-shared key (both required); revocation is a one-liner |
| T3 | Tampering | rogue change opens the perimeter (any/any pass, ssh on, alert-only IPS) | policy-as-code gate (PW001-PW007) runs in CI on every change |
| T4 | Tampering | soc-lite manipulated into blocking internal ranges | allowlist enforced in code (RFC1918); alias owned by soc-lite alone (PW007) |
| T5 | Repudiation | nobody can prove who blocked what and when | WAN block rules log; soc-lite prints one line per decision; eve.json retained 90 days |
| T6 | Information disclosure | telework traffic sniffed on hotel/cafe wifi | WireGuard ChaCha20-Poly1305; no cleartext management path (GUI is HTTPS, ssh off) |
| T7 | Information disclosure | DMZ pivot into LAN after app compromise | DMZ->LAN denied and logged (PW004 matrix); DMZ egress limited to tcp/443 |
| T8 | Denial of service | brute force / scan storm exhausts services | inline IPS drops known-bad patterns; soc-lite blocks repeat sources for 15 min |
| T9 | Denial of service | attacker floods soc-lite to exhaust memory | per-ip hit ring capped at 512 entries; unparseable sources ignored |
| T10 | Elevation of privilege | API token leak grants firewall control | token is read/write API-only, scoped in User Manager; GUI restricted to VPN (PW003); rotate on departure |
| T11 | Elevation of privilege | departed employee keeps a tunnel | revoke-peer.sh removes peer + profile + logs the revocation date |

## Residual risks (accepted, written down)

- A zero-day exploit that Suricata signatures do not know yet defeats
  layer 1; the sliding-window block still catches the scanner behaviour
  that surrounds real exploits.
- The lab uses a self-signed certificate for the pfSense GUI; production
  deployment should install a CA-signed cert for the management plane.
- soc-lite trusts eve.json contents; a compromised sensor could feed it
  poison. The allowlist bounds the blast radius to external addresses.
