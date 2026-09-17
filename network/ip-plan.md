# IP Plan & Zones

One firewall, four zones. Everything is deny-by-default; the only doors
are the ones listed here. The audit gate (`firewall/policy_check.py`)
enforces this matrix in CI, so a rule that drifts from the plan breaks
the build.

## Interfaces

| zone | interface | subnet | upstream vlan | purpose |
|------|-----------|--------|---------------|---------|
| WAN_UPLINK | igb0 | dhcp (lab: 203.0.113.2/24) | - | internet uplink, Suricata inline |
| LAN_CORP   | igb1 | 10.10.10.1/24 | 10 | office workstations, printers |
| DMZ_APPS   | igb2 | 10.20.20.1/24 | 20 | published application servers |
| VPN_REMOTE | wg0  | 10.99.0.1/22  | - | WireGuard telework pool |

The 10.99.0.0/22 pool gives room for about a thousand telework peers.
The gateway sits at 10.99.0.1; the first provisioned admin host is
10.99.0.10 and is the only source allowed to open the firewall GUI.

## Key hosts

| host | ip | notes |
|------|----|-------|
| edge-fw01 | 10.10.10.1 / 10.20.20.1 / 10.99.0.1 | pfSense CE 2.7+, Suricata, soc-lite |
| app-01 | 10.20.20.10 | DMZ application server, tcp/8443 |
| app-02 | 10.20.20.11 | DMZ application server, tcp/8443 |
| admin-laptop | 10.99.0.10 | management workstation, VPN-only |

## Traffic matrix

| from | to | allowed |
|------|----|---------|
| WAN | any | nothing (default deny, logged) |
| LAN_CORP | DMZ_APPS | tcp/8443 |
| LAN_CORP | internet | egress via NAT, DNS through the resolver |
| DMZ_APPS | internet | tcp/443 only (updates) |
| DMZ_APPS | LAN_CORP | nothing (logged) |
| VPN_REMOTE | DMZ_APPS | tcp/8443 |
| VPN_REMOTE | LAN_CORP | nothing (logged) |
| MGMT_HOSTS | firewall self | tcp/443 (GUI over VPN) |

Full rule text lives in `network/pfsense/config.baseline.xml`. The
suricata sensor watches WAN inline, and soc-lite converts its EVE alerts
into live blocks by populating the `SOC_AUTO_BLOCK` alias.
