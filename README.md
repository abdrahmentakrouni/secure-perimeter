# secure-perimeter

[![ci](https://github.com/abdrahmentakrouni/secure-perimeter/actions/workflows/ci.yml/badge.svg)](https://github.com/abdrahmentakrouni/secure-perimeter/actions/workflows/ci.yml)
[![release](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/abdrahmentakrouni/secure-perimeter/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![platform](https://img.shields.io/badge/platform-pfSense%20CE%202.7%2B-orange)

Automated perimeter defense built around **pfSense CE 2.7+**: an inline
Suricata IDS/IPS, a small daemon (soc-lite) that turns EVE alerts into
live firewall blocks through the pfSense REST API, and one-command
WireGuard onboarding for the remote workforce. A policy-as-code gate
audits the whole baseline in CI, so the perimeter cannot drift quietly.

## Why

Remote work and branch offices widened the company surface beyond the
office wall: espionage attempts, packet sniffing on hostile wifi, and
straight scans against anything that answers on the internet. A firewall
that only sits there is not enough - someone has to watch it and react
at 3am. This repo is the automation for that job: detect, block,
onboard, revoke, prove.

## What it does

1. **Detects and prevents automatically** - Suricata runs inline on WAN
   (block mode, not just alerts); soc-lite scores sources in a sliding
   window and cuts off repeat offenders for 15 minutes by editing a
   firewall alias over the REST API. Private ranges are allowlisted so
   it can never lock the company out of itself.
2. **Secures remote access** - one WireGuard tunnel for teleworkers and
   branch sites. `provision-peer.sh analyst-01` generates keys, a
   per-peer pre-shared key, the client profile and a QR code; the peer
   reaches the DMZ apps and nothing else. Revocation is one command.
3. **Proves the policy** - `firewall/policy_check.py` audits the pfSense
   baseline against the agreed matrix (7 checks, PW001-PW007) and CI
   fails if the perimeter config drifts.

## Architecture

```
                       internet
                          |
                 +------------------+
                 |   WAN_UPLINK     |
                 |   Suricata IPS   |  inline block mode
                 |   edge-fw01      |
                 |   pfSense CE 2.7+|
                 +------------------+
                    |       |       \
             +----------+ +----------+ +----------------+
             | LAN_CORP | | DMZ_APPS | | VPN_REMOTE     |
             | 10.10.10 | | 10.20.20 | | 10.99.0.0/22   |
             | staff    | | app-01/2 | | WireGuard wg0  |
             +----------+ +----------+ +----------------+
                                             ^
                                             | udp/51820
                                     teleworkers + branch sites
```

Full picture and failure modes: [docs/architecture.md](docs/architecture.md).
Address plan and traffic matrix: [network/ip-plan.md](network/ip-plan.md).

## Quickstart (lab)

```bash
# 1. install pfSense CE 2.7+, load the baseline, wire the API
#    (step by step: docs/runbooks/deploy-perimeter.md)

# 2. bootstrap the soc alias and reload the filter
export PF_HOST="https://192.168.1.1" PF_TOKEN="<api token>"
bash firewall/apply-firewall.sh

# 3. arm the auto-blocker against the live sensor log
python3 ids/soc-lite/soc_lite.py --tail /var/log/suricata/eve.json

# 4. onboard a teleworker in one command
export PF_WG_ENDPOINT="vpn.corp.example.tn:51820" PF_WG_PUBKEY="<server pubkey>"
bash vpn/provision-peer.sh analyst-01
```

## soc-lite in action (captured attack session, replayed in CI)

```text
[09:00:05] ignore 203.0.113.7 (1/3 high-severity hits in window)
[09:00:20] ignore 203.0.113.7 (2/3 high-severity hits in window)
[09:00:35] block 203.0.113.7 (3+ high-severity alerts in 120s window; last: ET SCAN Suricata Portscan (sid=2200074))
[09:00:35] would block 203.0.113.7 for 900s (alias SOC_AUTO_BLOCK)
[09:00:36] ignore 203.0.113.7 (already blocked for another 899s)
[09:00:40] ignore 198.51.100.23 (low severity 3)
[09:00:45] ignore 10.99.0.10 (allowlisted source)
[09:01:00] ignore 198.51.100.77 (1/3 high-severity hits in window)
[09:01:15] block 198.51.100.77 (3+ high-severity alerts in 120s window; last: SOC SMB from external network (sid=1000002))
summary: events=14 blocks=2 ignores=9 mode=dry-run
```

Two attackers crossed the threshold and were cut off; the low-noise
source was scored but ignored; the internal admin laptop was allowlisted
throughout. The CI `demo` job replays this exact session on every push.

## Repo map

```
network/   ip plan + pfSense config.baseline.xml (audited artifact)
ids/       suricata rules + tuning, soc-lite auto-blocker + tests
firewall/  apply-firewall.sh, policy_check.py (the CI gate)
vpn/       provision-peer.sh, revoke-peer.sh, client template
docs/      architecture, threat model, policy matrix, runbooks,
           purple-team test plan
examples/  captured EVE attack session for the demo
```

## Verification

```bash
make lint      # shellcheck + yamllint
make test      # pytest suite for the scorer (11 cases)
make policy    # audit the baseline: POLICY PASS 7/7
make demo      # replay the captured attack, watch it get blocked
```

Ten manual attack replays (port scan, ssh brute force, smb from the
internet, vpn reachability matrix, block expiry, unblock drill) are in
[docs/purple-team-tests.md](docs/purple-team-tests.md).

## Threat model and policy

- [docs/threat-model.md](docs/threat-model.md) - STRIDE, 11 threats,
  each mapped to a control, residual risks written down
- [docs/policy-matrix.md](docs/policy-matrix.md) - every rule, where it
  is enforced, and which machine keeps it true
- [docs/runbooks/](docs/runbooks/) - deploy, vpn onboarding, incident
  response

## License

MIT - see [LICENSE](LICENSE).
