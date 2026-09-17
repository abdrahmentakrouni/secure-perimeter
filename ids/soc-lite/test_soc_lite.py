import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import soc_lite  # noqa: E402


def make_alert(ts, ip="203.0.113.7", sev=1, sid=1000001, port=22,
               sig="SOC test signature"):
    return soc_lite.Alert(ts=ts, src_ip=ip, dest_port=port,
                          signature_id=sid, signature=sig, severity=sev)


ALLOWLIST = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def eve_line(src="203.0.113.7", dst="10.10.10.5", port=22, sev=1,
             sid=1000001, sig="SOC SSH brute force burst",
             ts="2026-09-10T09:00:05.123456+0000", etype="alert"):
    return '{"timestamp":"%s","event_type":"%s","src_ip":"%s","dest_ip":"%s",' \
           '"proto":"TCP","dest_port":%d,"alert":{"action":"blocked",' \
           '"signature_id":%d,"signature":"%s","severity":%d}}' % (
               ts, etype, src, dst, port, sid, sig, sev)


# ---------- parse_event ----------

def test_parse_event_yields_alert():
    alert = soc_lite.parse_event(eve_line())
    assert alert is not None
    assert alert.src_ip == "203.0.113.7"
    assert alert.dest_port == 22
    assert alert.signature_id == 1000001
    assert alert.severity == 1
    assert alert.ts > 0


def test_parse_event_skips_noise():
    assert soc_lite.parse_event("") is None
    assert soc_lite.parse_event("not json at all") is None
    assert soc_lite.parse_event('{"event_type":"stats","stats":{}}') is None
    assert soc_lite.parse_event('{"timestamp":"oops","event_type":"alert"}') is None


def test_parse_ts_handles_offsets():
    value = soc_lite.parse_ts("2026-09-10T09:00:35.123456+0000")
    assert value > 1_700_000_000


# ---------- scorer ----------

def new_state(window=120, threshold=3, ttl=900):
    return soc_lite.OffenderState(window=window, threshold=threshold, ttl=ttl)


def test_low_severity_never_scores():
    state = new_state()
    for i in range(3):
        action = state.decide(make_alert(1000 + i, sev=3), ALLOWLIST)
    assert action.kind == "ignore"
    assert "low severity" in action.reason


def test_allowlisted_source_never_blocks():
    state = new_state()
    for i in range(6):
        action = state.decide(make_alert(1000 + i, ip="10.99.0.10"), ALLOWLIST)
    assert action.kind == "ignore"
    assert "allowlisted" in action.reason


def test_unparseable_ip_is_treated_as_allowlisted():
    state = new_state()
    action = state.decide(make_alert(1000, ip="not-an-ip"), ALLOWLIST)
    assert action.kind == "ignore"


def test_block_after_threshold():
    state = new_state()
    assert state.decide(make_alert(1000), ALLOWLIST).kind == "ignore"
    assert state.decide(make_alert(1030), ALLOWLIST).kind == "ignore"
    block = state.decide(make_alert(1060, sid=1000003,
                                    sig="SOC ICMP sweep"), ALLOWLIST)
    assert block.kind == "block"
    assert "3+ high-severity" in block.reason


def test_window_expires_without_block():
    state = new_state(window=120)
    state.decide(make_alert(1000), ALLOWLIST)
    state.decide(make_alert(1090), ALLOWLIST)
    action = state.decide(make_alert(1150), ALLOWLIST)  # first hit aged out
    assert action.kind == "ignore"


def test_no_repeat_while_block_active():
    state = new_state()
    for ts in (1000, 1030, 1060):
        action = state.decide(make_alert(ts), ALLOWLIST)
    assert action.kind == "block"
    nxt = state.decide(make_alert(1070), ALLOWLIST)
    assert nxt.kind == "ignore"
    assert "already blocked" in nxt.reason


def test_reblock_after_ttl_served():
    state = new_state(ttl=300)
    for ts in (1000, 1030, 1060):
        state.decide(make_alert(ts), ALLOWLIST)
    # expiry at 1360; offender comes back at 1400+
    state.decide(make_alert(1400), ALLOWLIST)
    state.decide(make_alert(1430), ALLOWLIST)
    action = state.decide(make_alert(1460), ALLOWLIST)
    assert action.kind == "block"


# ---------- dry-run actor ----------

def test_dry_run_actor_never_touches_network():
    actor = soc_lite.DryRunActor()
    text = actor.execute("203.0.113.7", "test reason")
    assert "would block 203.0.113.7" in text
    assert soc_lite.DEFAULT_ALIAS in text
