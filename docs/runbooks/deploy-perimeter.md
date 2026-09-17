# Runbook: Deploy the Perimeter

Fresh install of edge-fw01 from nothing to fully armed. Time budget:
about an hour, most of it waiting for rule reloads.

## 1. Base pfSense install

1. Install pfSense CE 2.7+ on the box (four nics expected: igb0-igb3).
2. Assign interfaces per `network/ip-plan.md` (wan / lan / opt1 DMZ /
   opt2 VPN_REMOTE).
3. Set LAN to 10.10.10.1/24, opt1 to 10.20.20.1/24, opt2 to 10.99.0.1/22.

## 2. Load the baseline

1. System > Config > restore: upload `network/pfsense/config.baseline.xml`
   (partial restore, area: all). The baseline carries zones, aliases,
   the filter rules, Suricata settings and the WireGuard tunnel shell.
2. Edit the placeholders afterwards: the server WireGuard keypair
   (VPN > WireGuard, regenerate), the GUI certificate, DNS.
3. Sanity check: Diagnostics > Rules file or GUI Firewall > Rules shows
   the nine baseline rules. `firewall/policy_check.py` against an
   exported config must say `POLICY PASS: 7/7`.

## 3. Wire the IPS

1. System > Package Manager > Available Packages: install Suricata.
2. Interfaces > WAN > Suricata: Enabled, Block Mode ON, EVE JSON log ON.
3. Categories: ET-open + app-detect; paste `ids/suricata/local.rules`
   into custom rules; load `ids/suricata/suppress.list` as the suppress
   list.
4. Prove it: run purple-team case 1 (port scan) from outside; expect
   drops in /var/log/filter.log within seconds.

## 4. Open the API

1. Install the REST API package (jaredhendrickson13/pfsense-api).
2. System > User Manager: create user `soc-lite`, generate an API token,
   scope it to firewall aliases only. Store the token in your password
   manager, never in a file.
3. From the soc-lite host: `bash firewall/apply-firewall.sh` with
   PF_HOST and PF_TOKEN exported. Expect `[+] filter reloaded`.

## 5. Arm soc-lite

1. Copy `ids/soc-lite/` to the admin host (it can live anywhere with
   network access to the firewall API).
2. Smoke test: `python3 ids/soc-lite/soc_lite.py --file
   examples/eve-sample.jsonl --dry-run` must print two `would block`
   lines and a summary.
3. Run it for real as a service (systemd unit or tmux to start):
   `python3 ids/soc-lite/soc_lite.py --tail /var/log/suricata/eve.json`
   with PF_HOST and PF_TOKEN exported.

## 6. First teleworkers

1. Export the server public key and endpoint, then per worker:
   `bash vpn/provision-peer.sh analyst-01` (see vpn-onboarding.md).
2. Purple-team cases 7 and 8: handshake works, LAN is not reachable.
3. Update this runbook with any deviation you had to make. Baseline and
   reality must stay the same picture, or the audit gate loses meaning.
