# Suricata on the perimeter

Installed as a pfSense package on WAN_UPLINK in inline block mode
(`block: on` in the baseline config), fed by the ET-open ruleset plus the
custom rules in `local.rules` (sid pool 1000001+). Inline means alerts
become drops the moment the sensor sees them; soc-lite adds the
second layer: repeat offenders get cut off entirely for 15 minutes.

Files:

- `local.rules` - custom signatures (ssh brute force, smb from outside,
  icmp sweeps, outbound irc, dns tunnel heuristic)
- `suppress.list` - one sid per line with a reason; every line is audit
  surface and gets reviewed on tuning day

The EVE JSON log (`/var/log/suricata/eve.json`) is what soc-lite tails.
Deployment steps live in `docs/runbooks/deploy-perimeter.md`; attack
replays to validate the rules are in `docs/purple-team-tests.md`.
