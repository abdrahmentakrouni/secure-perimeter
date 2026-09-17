#!/usr/bin/env python3
"""Policy-as-code audit for the pfSense perimeter baseline.

Reads the baseline config.xml and verifies the invariants the security
team agreed on (see docs/policy-matrix.md). Any violation exits 1 so the
CI gate fails loudly instead of letting the perimeter drift quietly.

Checks:
  PW001  explicit, logged default deny on WAN
  PW002  no pass rule is any/any on both sides
  PW003  GUI port 443 is never passed from source "any"
  PW004  VPN clients are explicitly blocked from LAN_CORP
  PW005  Suricata runs inline (block mode) on WAN
  PW006  WireGuard telework tunnel present and enabled
  PW007  SOC_AUTO_BLOCK alias reserved and empty for soc-lite
"""
import argparse
import sys
import xml.etree.ElementTree as ET

CHECKS = []


def check(cid):
    def deco(fn):
        CHECKS.append((cid, fn))
        return fn
    return deco


def find_rules(root):
    return root.findall("./filter/rule")


def source_is_any(rule):
    src = rule.find("source")
    return src is not None and src.find("any") is not None


def dest_is_any(rule):
    dst = rule.find("destination")
    return dst is not None and dst.find("any") is not None


def dest_port(rule):
    dst = rule.find("destination")
    if dst is None:
        return ""
    port = dst.find("port")
    return (port.text or "").strip() if port is not None else ""


@check("PW001")
def pw001_wan_default_deny(root):
    for rule in find_rules(root):
        if (rule.findtext("interface", "").strip() == "wan"
                and rule.findtext("type", "").strip() == "block"
                and rule.find("log") is not None):
            return None
    return "no explicit logged default deny found on WAN"


@check("PW002")
def pw002_no_pass_any_any(root):
    bad = []
    for rule in find_rules(root):
        if rule.findtext("type", "").strip() != "pass":
            continue
        if source_is_any(rule) and dest_is_any(rule):
            bad.append(rule.findtext("descr", "?").strip())
    if bad:
        return "pass rule(s) any->any: " + ", ".join(bad)
    return None


@check("PW003")
def pw003_gui_port_restricted(root):
    bad = []
    for rule in find_rules(root):
        if rule.findtext("type", "").strip() != "pass":
            continue
        if dest_port(rule) == "443" and source_is_any(rule):
            bad.append(rule.findtext("descr", "?").strip())
    if bad:
        return "port 443 passed from source any: " + ", ".join(bad)
    return None


@check("PW004")
def pw004_vpn_lan_isolation(root):
    for rule in find_rules(root):
        if (rule.findtext("interface", "").strip() == "opt2"
                and rule.findtext("type", "").strip() == "block"
                and "LAN_CORP_NET" in (rule.findtext("destination/address", "") or "")):
            return None
    return "no explicit VPN->LAN block rule on VPN_REMOTE (opt2)"


@check("PW005")
def pw005_ips_inline(root):
    cfg = root.find("./installedpackages/suricata/config")
    if cfg is None:
        return "suricata package config missing from baseline"
    if cfg.findtext("enable", "").strip() != "on":
        return "suricata detection is not enabled"
    if cfg.findtext("block", "").strip() != "on":
        return "suricata runs in alert-only mode (inline blocking off)"
    return None


@check("PW006")
def pw006_wireguard_present(root):
    for tunnel in root.findall("./wireguard/tunnel"):
        if (tunnel.findtext("enabled", "").strip() == "on"
                and tunnel.findtext("port", "").strip() == "51820"):
            return None
    return "no enabled WireGuard tunnel on udp/51820"


@check("PW007")
def pw007_soc_alias_reserved(root):
    for alias in root.findall("./aliases/alias"):
        if alias.findtext("name", "").strip() == "SOC_AUTO_BLOCK":
            addr = (alias.findtext("address") or "").strip()
            if addr:
                return "SOC_AUTO_BLOCK alias is not empty (soc-lite owns it)"
            return None
    return "SOC_AUTO_BLOCK alias missing (soc-lite has nowhere to block)"


def audit(root):
    findings = []
    for cid, fn in CHECKS:
        msg = fn(root)
        if msg:
            findings.append((cid, msg))
    return findings


def main():
    ap = argparse.ArgumentParser(
        description="audit pfSense baseline against the perimeter policy")
    ap.add_argument("config", help="path to pfSense config.xml baseline")
    ap.add_argument("--strict", action="store_true",
                    help="fail on any finding (default behaviour, kept for clarity)")
    args = ap.parse_args()
    try:
        tree = ET.parse(args.config)
    except (ET.ParseError, OSError) as exc:
        print(f"POLICY FAIL: cannot read baseline: {exc}")
        return 2
    findings = audit(tree.getroot())
    for cid, msg in findings:
        print(f"  FAIL {cid}: {msg}")
    passed = len(CHECKS) - len(findings)
    if findings:
        print(f"POLICY FAIL: {passed}/{len(CHECKS)} checks passed, "
              f"{len(findings)} violation(s)")
        return 1
    print(f"POLICY PASS: {len(CHECKS)}/{len(CHECKS)} checks satisfied - "
          "baseline matches the agreed matrix")
    return 0


if __name__ == "__main__":
    sys.exit(main())
