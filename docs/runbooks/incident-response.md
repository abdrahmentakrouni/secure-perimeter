# Runbook: Incident Response (Perimeter Edition)

When something trips the wire. Keep it boring: identify, contain,
eject, learn. Times are minutes from first alert.

## Triage (minute 0-10)

1. What fired? `grep '"signature_id":<sid>' /var/log/suricata/eve.json |
   tail -20` or search the soc-lite log for the block decision.
2. Who is it? external address -> treat as hostile until proven lazy
   (a scanner from a cloud provider is still a scanner). Internal
   address -> go straight to containment; internal hosts should never
   trip WAN signatures.
3. Scope: same source across zones? `grep '<ip>' /var/log/filter.log`

## Containment (minute 10-15)

- If soc-lite already blocked the source: done, verify with
  `curl -m 3` from a WAN-side box that the address is dead.
- Manual block of a new source:
  `python3 ids/soc-lite/soc_lite.py --unblock <ip>` is the reverse
  operation; for a manual *add*, use the pfSense GUI alias editor or:
  `curl -sk -X PUT "$PF_HOST/api/v1/firewall/alias" ...` with the
  current address list plus the new entry, then apply-firewall.sh.
- Sustained attack from many sources: enable pfSense's packet capture,
  note the pattern, add a targeted Suricata rule (sid pool 1000001+)
  rather than widening any blanket rule.

## Evidence (before you eject anything)

1. Snapshot the state: copy eve.json, filter.log and the soc-lite log
   lines for the window. Timestamps are UTC.
2. Record: source, first seen, last seen, signatures hit, actions taken
   (who, when, what command). The repudiation threat (T5) is answered
   by boring notes.

## Eject and harden (minute 15-30)

1. Keep the block in place for the TTL or make it permanent by adding
   the address to a dedicated `IR_HELD` alias (not SOC_AUTO_BLOCK -
   that one is soc-lite's, policy PS04/PW007).
2. If the attack exposed a service it should not have reached, fix the
   matrix: update config.baseline.xml, let the CI gate check it, apply
   through the API.
3. If a signature was noisy enough to need suppression: add the sid to
   ids/suricata/suppress.list with a reason, in a PR, not on the box.

## After (same day)

- One paragraph in the team channel: what happened, what worked, what
  the gap was. If the gap needs a code change, open the PR before
  closing the incident ticket. The purple-team plan is the checklist
  for the next drill.
