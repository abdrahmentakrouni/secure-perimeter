# Architecture

## Big picture

edge-fw01 is the single door between the company and the internet. Four
zones hang behind it, every packet from the internet is dropped unless a
rule says otherwise, and two automation layers make the door react on
its own: Suricata watches the wire inline, soc-lite converts repeated
attack alerts into live firewall blocks.

```
                       internet
                          |
                   [ scans, brute force,
                     packet injection ]
                          |
                 +------------------+
                 |   WAN_UPLINK     |
                 |   Suricata IPS   |  inline block mode (drops, not just logs)
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
                                     teleworkers + admin laptop
                                     (branch offices, teletravail)
```

## The three layers

1. **Detection + prevention (ids/)** - Suricata runs on WAN in inline
   block mode: matching packets are dropped as they cross the wire, not
   merely logged. The ET-open ruleset carries the known-bad signatures;
   `ids/suricata/local.rules` adds perimeter-specific ones (ssh brute
   bursts, smb arriving from outside, icmp sweeps, outbound irc).

2. **Automated response (ids/soc-lite/)** - soc-lite tails
   `/var/log/suricata/eve.json`, scores each source address in a sliding
   120 s window, and once a source crosses the threshold (3 high-severity
   alerts) it is inserted into the `SOC_AUTO_BLOCK` alias through the
   pfSense REST API and the filter reloads. Blocks expire after 15
   minutes; private ranges are allowlisted so the tool can never lock
   the company out of itself.

3. **Secure remote access (vpn/)** - one WireGuard tunnel serves the
   whole remote workforce. `provision-peer.sh` turns onboarding into a
   one-liner: keypair, per-peer pre-shared key, client profile, optional
   QR for mobile, optional API registration on the firewall. Revocation
   is the same one-liner in reverse. A teleworker reaches the DMZ app
   servers and nothing else - VPN-to-LAN is denied and logged.

## Data flow of an attack

```
nmap sweep from 203.0.113.7
  -> WAN nic sees SYN packets
  -> suricata writes severity-2 alerts to eve.json
  -> soc-lite reads them, counts 3 hits in the window
  -> POST /api/v1/firewall/alias  (SOC_AUTO_BLOCK += 203.0.113.7)
  -> POST /api/v1/firewall/apply
  -> every further packet from that address dies at the WAN nic
```

## Failure modes (and why they are acceptable)

- **soc-lite dies**: Suricata still drops inline on signatures; the
  auto-block layer just stops growing. Restart the service; nothing to
  unwind because aliases are idempotent.
- **pfSense API unreachable**: soc-lite prints the API error and keeps
  scanning; offenders are reported instead of blocked. Monitoring pokes
  the API health endpoint every minute (see incident-response runbook).
- **Suricata overwhelmed**: packet drop counters land in EVE stats
  events; the purple-team plan includes a check for them.
