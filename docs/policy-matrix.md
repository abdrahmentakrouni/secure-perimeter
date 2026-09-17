# Policy Matrix

Every rule the perimeter enforces, where it is enforced, and what breaks
if it stops being true. The rightmost column is the machine that keeps
us honest: `firewall/policy_check.py` runs in CI and fails the build if
the baseline drifts.

| id | policy | enforcement | audit |
|----|--------|-------------|-------|
| PW001 | the internet gets nothing by default; every rejected WAN packet is logged | explicit default deny rule with `log` on WAN | PW001 in policy_check.py |
| PW002 | no rule may pass anything from anywhere to anywhere | rule review discipline + baseline audit | PW002 |
| PW003 | the firewall GUI is reachable only from VPN (MGMT_HOSTS), never from source any | pass rules for tcp/443 carry explicit sources | PW003 |
| PW004 | teleworkers reach the DMZ apps and nothing else | block rule VPN_REMOTE -> LAN_CORP_NET, logged | PW004 |
| PW005 | known-bad traffic is dropped on the wire, not just observed | Suricata inline with `block: on` on WAN | PW005 |
| PW006 | remote access rides one encrypted tunnel on udp/51820 | WireGuard tunnel enabled in baseline | PW006 |
| PW007 | soc-lite owns exactly one alias and nothing else touches it | SOC_AUTO_BLOCK host alias reserved, empty at rest | PW007 |
| PS01  | attackers that persist are cut off automatically, then forgiven | soc-lite: 3 high-severity alerts / 120 s -> 15 min block | pytest suite + CI demo |
| PS02  | internal addresses are never auto-blocked | soc-lite allowlist (RFC1918) | pytest suite |
| PS03  | every suppression is written down or it does not exist | ids/suricata/suppress.list, one sid per line with reason | peer review |
| PS04  | ssh to the firewall is off; management is GUI-over-VPN only | `<disablessh/>` in baseline | PW001/PW003 indirectly + runbook |
| PS05  | DMZ may pull updates from the internet and reach nothing internal | tcp/443 egress only + logged block to LAN | PW002/PW004 |

## Making a policy change

1. Open a PR that touches `network/pfsense/config.baseline.xml` and,
   when needed, `docs/policy-matrix.md`.
2. CI runs the audit gate; a violation means the PR does not merge.
3. After merge, push the live change through `firewall/apply-firewall.sh`
   or the pfSense API, then re-run the gate against the live export.
