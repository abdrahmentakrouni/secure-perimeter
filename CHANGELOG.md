# Changelog

All notable changes to secure-perimeter are documented here.
Format follows Keep a Changelog; versioning follows SemVer.

## [1.0.0] - 2026-09-18

### Added
- pfSense CE 2.7+ hardened baseline config covering four zones:
  WAN_UPLINK, LAN_CORP, DMZ_APPS, VPN_REMOTE (WireGuard telework pool)
- Suricata custom ruleset (ids/suricata/local.rules) with suppress list
  and tuning notes
- soc-lite: Suricata EVE JSON triage daemon that auto-blocks repeat
  offenders through the pfSense REST API (host alias SOC_AUTO_BLOCK +
  filter reload), with dry-run mode, allowlist, sliding-window scoring,
  block TTL and a pytest suite
- WireGuard telework tooling: provision-peer.sh / revoke-peer.sh
  one-liners with per-peer pre-shared keys and optional QR onboarding
- firewall/apply-firewall.sh: idempotent alias bootstrap + filter apply
- policy_check.py: policy-as-code audit gate (7 checks, PW001-PW007)
  wired into CI so the baseline cannot drift silently
- Docs: architecture, threat model (STRIDE), policy matrix, three
  runbooks (deploy, VPN onboarding, incident response) and a 10-case
  purple-team test plan
- CI: shellcheck + yamllint + pytest + policy gate + a live soc-lite
  demo that proves detection and blocking on every push
