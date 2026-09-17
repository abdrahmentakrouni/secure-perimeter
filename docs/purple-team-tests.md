# Purple-Team Test Plan

Ten replays that prove the perimeter does what the docs claim. Run them
from the WAN side (a lab box outside the firewall) unless noted. Every
case lists the exact command, the expected observation, and where the
evidence lands. Evidence files live on edge-fw01:
`/var/log/suricata/eve.json` and `/var/log/filter.log`.

| # | attack | command | expected | evidence |
|---|--------|---------|----------|----------|
| 1 | tcp port scan | `nmap -sS -Pn --top-ports 100 203.0.113.2` | ET SCAN alerts fire; soc-lite blocks the source at hit 3; further packets die | eve.json sids 2200074; filter.log drops |
| 2 | ssh brute force | `hydra -l admin -P wordlist.txt ssh://203.0.113.2` | SOC SSH brute sig (1000001) fires at 8 tries/60 s; soc-lite blocks | eve.json sid 1000001 |
| 3 | smb from internet | `nc -vz 203.0.113.2 445` | sig 1000002 + WAN default deny; connection refused | eve.json + filter.log |
| 4 | icmp sweep | `nmap -sn 203.0.113.0/24` | SOC ICMP sweep (1000003) after 20 pings/10 s | eve.json |
| 5 | outbound c2 channel | `nc 6667` from LAN host to external | SOC outbound IRC (1000004) alerts | eve.json |
| 6 | dns tunnel heuristic | `dig @10.10.10.1 longchain.example.tn` from WAN | SOC long DNS answer (1000005) if payload > 180 B | eve.json |
| 7 | vpn happy path | `wg-quick up analyst-01` from remote box | handshake completes; 10.20.20.10:8443 reachable | `wg show` latest handshake |
| 8 | vpn reachability matrix | from tunnel: `curl -m 3 http://10.10.10.5` | blocked and logged (VPN->LAN deny) | filter.log opt2 drop |
| 9 | auto-block expiry | stop the attack, wait 15 min, rescan | source unblocked after TTL; re-triggers on new hits | soc-lite log lines |
| 10 | unblock drill | `python3 ids/soc-lite/soc_lite.py --unblock 203.0.113.7` | alias updated + filter reloaded; IR runbook step verified | command output |

## Pass criteria

- Cases 1-5: alert present in eve.json AND a drop in filter.log within
  the same minute.
- Cases 7-8: exactly the documented matrix, nothing more.
- Cases 9-10: soc-lite log shows the block expiring / the manual
  unblock, and the alias no longer contains the address.

## Regression

After every ruleset or policy change, re-run cases 1, 2, 7, 8. The CI
demo job replays the same logic against `examples/eve-sample.jsonl` on
every push, so the scoring code cannot rot silently between drills.
