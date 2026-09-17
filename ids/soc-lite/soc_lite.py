#!/usr/bin/env python3
"""soc-lite - Suricata EVE triage daemon with pfSense enforcement.

Tails Suricata eve.json, scores offenders in a sliding window, and blocks
repeat actors by inserting them into a pfSense host alias through the
REST API (github.com/jaredhendrickson13/pfsense-api), followed by a
filter reload. Allowlisted ranges are never touched. Blocks expire after
a TTL so a scanner that stops does not stay burned forever.

Dry-run mode makes no network calls and prints the decisions it would
take - that is what CI runs against the captured sample, so the
detection logic proves itself on every push.

Usage:
  # watch the sensor live (needs PF_HOST + PF_TOKEN)
  python3 ids/soc-lite/soc_lite.py --tail /var/log/suricata/eve.json

  # replay a captured session, no firewall touched
  python3 ids/soc-lite/soc_lite.py --file examples/eve-sample.jsonl --dry-run

  # incident response: lift a block manually
  python3 ids/soc-lite/soc_lite.py --unblock 203.0.113.7
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass

DEFAULT_THRESHOLD = 3      # high-severity alerts before a block
DEFAULT_WINDOW = 120       # sliding window in seconds
DEFAULT_TTL = 900          # how long a block stays in the alias
DEFAULT_ALIAS = "SOC_AUTO_BLOCK"
DEFAULT_ALLOWLIST = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
HIGH_SEVERITY_MAX = 2      # suricata: 1-2 = attack, 3+ = informational
MAX_TRACKED_PER_IP = 512   # keep memory honest against a flood


@dataclass(frozen=True)
class Alert:
    ts: float
    src_ip: str
    dest_port: int
    signature_id: int
    signature: str
    severity: int


@dataclass
class Action:
    kind: str      # block | ignore
    ip: str
    reason: str


def parse_ts(raw: str) -> float:
    try:
        return datetime.datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return time.mktime(time.strptime(raw[:19], "%Y-%m-%dT%H:%M:%S"))


def parse_event(line: str) -> Alert | None:
    """One EVE JSON line -> Alert, or None for anything we do not score."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or obj.get("event_type") != "alert":
        return None
    alert = obj.get("alert") or {}
    try:
        return Alert(
            ts=parse_ts(obj["timestamp"]),
            src_ip=obj["src_ip"],
            dest_port=int(obj.get("dest_port", 0)),
            signature_id=int(alert.get("signature_id", 0)),
            signature=str(alert.get("signature", "unknown")),
            severity=int(alert.get("severity", 3)),
        )
    except (KeyError, TypeError, ValueError):
        return None


class OffenderState:
    """Sliding-window scorer with allowlist, TTL and no-repeat semantics."""

    def __init__(self, window: int, threshold: int, ttl: int):
        self.window = window
        self.threshold = threshold
        self.ttl = ttl
        self.hits: dict[str, deque] = defaultdict(deque)
        self.blocked: dict[str, float] = {}  # ip -> expiry ts

    def is_allowlisted(self, ip: str, allowlist: list[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable source: never act on it
        return any(addr in ipaddress.ip_network(net) for net in allowlist)

    def decide(self, alert: Alert, allowlist: list[str]) -> Action:
        ip = alert.src_ip
        if self.is_allowlisted(ip, allowlist):
            return Action("ignore", ip, "allowlisted source")
        if alert.severity > HIGH_SEVERITY_MAX:
            return Action("ignore", ip, f"low severity {alert.severity}")

        now = alert.ts
        expiry = self.blocked.get(ip)
        if expiry:
            if expiry > now:
                return Action("ignore", ip,
                              f"already blocked for another {int(expiry - now)}s")
            del self.blocked[ip]  # TTL served; offender re-earns a block

        q = self.hits[ip]
        q.append(now)
        while q and q[0] < now - self.window:
            q.popleft()
        while len(q) > MAX_TRACKED_PER_IP:
            q.popleft()

        if len(q) >= self.threshold:
            self.blocked[ip] = now + self.ttl
            q.clear()
            return Action(
                "block", ip,
                f"{self.threshold}+ high-severity alerts in {self.window}s "
                f"window; last: {alert.signature} (sid={alert.signature_id})")
        return Action("ignore", ip,
                      f"{len(q)}/{self.threshold} high-severity hits in window")


class PfsenseApi:
    """Thin client for the pfSense REST API (alias + filter apply)."""

    def __init__(self, host: str, token: str, alias_name: str = DEFAULT_ALIAS):
        self.host = host.rstrip("/")
        self.token = token
        self.alias = alias_name
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False   # lab boxes run self-signed certs
        self.ctx.verify_mode = ssl.CERT_NONE

    def _call(self, method: str, path: str, body: dict | None = None) -> str:
        url = f"{self.host}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Authorization": self.token,
                     "Content-Type": "application/json",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, context=self.ctx, timeout=10) as resp:
            return resp.read().decode()

    def _alias_address_list(self) -> list[str]:
        raw = self._call("GET", f"/api/v1/firewall/alias?name={self.alias}")
        data = json.loads(raw) if raw else {}
        entries = data.get("data", data if isinstance(data, list) else [])
        for entry in entries if isinstance(entries, list) else []:
            if entry.get("name") == self.alias:
                return [a for a in (entry.get("address") or "").split() if a]
        return []

    def _push_alias(self, addresses: list[str]) -> None:
        self._call("PUT", "/api/v1/firewall/alias",
                   {"name": self.alias, "type": "host",
                    "descr": "soc-lite auto block list (managed)",
                    "address": " ".join(addresses)})
        self._call("POST", "/api/v1/firewall/apply")

    def add_to_alias(self, ip: str) -> str:
        addresses = self._alias_address_list()
        if ip in addresses:
            return f"{ip} already in alias {self.alias}"
        addresses.append(ip)
        self._push_alias(addresses)
        return f"{ip} added to alias {self.alias} + filter reloaded"

    def remove_from_alias(self, ip: str) -> str:
        addresses = self._alias_address_list()
        if ip not in addresses:
            return f"{ip} not present in alias {self.alias}"
        addresses.remove(ip)
        self._push_alias(addresses)
        return f"{ip} removed from alias {self.alias} + filter reloaded"


class DryRunActor:
    def execute(self, ip: str, _reason: str) -> str:
        return f"would block {ip} for {DEFAULT_TTL}s (alias {DEFAULT_ALIAS})"


class LiveActor:
    def __init__(self, api: PfsenseApi):
        self.api = api

    def execute(self, ip: str, _reason: str) -> str:
        try:
            return "blocked: " + self.api.add_to_alias(ip)
        except (urllib.error.URLError, OSError) as exc:
            return f"pfSense API error ({exc}) - {ip} NOT blocked, check PF_HOST"


def run_stream(lines, state: OffenderState, allowlist: list[str],
               actor, label: str) -> int:
    counts = {"block": 0, "ignore": 0, "events": 0}
    for line in lines:
        counts["events"] += 1
        alert = parse_event(line)
        if alert is None:
            continue
        action = state.decide(alert, allowlist)
        counts[action.kind] += 1
        stamp = datetime.datetime.fromtimestamp(
            alert.ts, datetime.timezone.utc).strftime("%H:%M:%S")
        if action.kind == "block":
            print(f"[{stamp}] block {alert.src_ip} ({action.reason})",
                  flush=True)
            print(f"[{stamp}] {actor.execute(alert.src_ip, action.reason)}",
                  flush=True)
        else:
            print(f"[{stamp}] ignore {alert.src_ip} ({action.reason})",
                  flush=True)
    print(f"summary: events={counts['events']} blocks={counts['block']} "
          f"ignores={counts['ignore']} mode={label}", flush=True)
    return 0


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--file", help="replay one EVE file, then exit")
    src.add_argument("--tail", help="follow an EVE file like tail -f")
    src.add_argument("--unblock", metavar="IP",
                     help="lift a manual block and exit (needs live API)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print decisions, never call the firewall")
    ap.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    ap.add_argument("--alias", default=DEFAULT_ALIAS)
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST,
                    help="comma separated networks, e.g. 10.0.0.0/8,192.168.0.0/16")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    allowlist = [n.strip() for n in args.allowlist.split(",") if n.strip()]

    if args.unblock:
        host, token = os.environ.get("PF_HOST"), os.environ.get("PF_TOKEN")
        if not (host and token):
            print("error: --unblock needs PF_HOST and PF_TOKEN in env", file=sys.stderr)
            return 2
        api = PfsenseApi(host, token, alias_name=args.alias)
        print(api.remove_from_alias(args.unblock))
        return 0

    state = OffenderState(window=args.window, threshold=args.threshold,
                          ttl=args.ttl)

    if args.dry_run:
        actor = DryRunActor()
        label = "dry-run"
    else:
        host, token = os.environ.get("PF_HOST"), os.environ.get("PF_TOKEN")
        if not (host and token):
            print("error: live mode needs PF_HOST and PF_TOKEN "
                  "(or pass --dry-run)", file=sys.stderr)
            return 2
        actor = LiveActor(PfsenseApi(host, token, alias_name=args.alias))
        label = "live"

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            return run_stream(fh, state, allowlist, actor, label)

    def _follow(path: str):
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)  # start at the end, then watch
            while True:
                line = fh.readline()
                if line:
                    yield line
                else:
                    time.sleep(1.0)

    source = _follow(args.tail) if args.tail else sys.stdin
    return run_stream(source, state, allowlist, actor, label)


if __name__ == "__main__":
    sys.exit(main())
