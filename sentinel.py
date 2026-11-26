import hashlib
import hmac
import math
import os
import sqlite3
import statistics
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional


# --- Configuration -----------------------------------------------------------

# The pseudonymization key is read from the environment so it never lives in
# source control. A demo key is used only when none is set, with a warning.
_DEMO_KEY = b"aegis-demo-key-NOT-FOR-PRODUCTION"
HMAC_KEY_ENV = "AEGIS_HMAC_KEY"

SPEED_LIMIT_UPS = 120.0       # peak movement speed (units/sec)
VALUE_SPIKE = 5000.0          # single-event ledger delta
BOT_MIN_EVENTS = 10           # need this many events before judging cadence
BOT_MAX_DT_STDEV = 0.05       # seconds
BOT_MAX_CV = 0.05             # coefficient of variation of inter-action gaps
BOT_MAX_UNIQUE_RATIO = 0.25   # share of distinct actions
MIN_DT = 1e-3                 # floor for duplicate timestamps

# Severity is ranked so a finding can only ever be raised, never lowered.
SEVERITY_RANK = {"CLEAN": 0, "HIGH": 1, "CRITICAL": 2}

SUGGESTED_ACTION = {
    "speed": "Suspend pending review; capture movement/packet logs",
    "value": "Freeze trades; open rollback audit on the ledger",
    "bot": "Flag for bot review; add to automation watchlist",
}


def get_hmac_key() -> bytes:
    key = os.environ.get(HMAC_KEY_ENV)
    if key:
        return key.encode("utf-8")
    print(
        f"[warn] {HMAC_KEY_ENV} not set; using demo key. "
        "Set it before running on real telemetry.",
        file=sys.stderr,
    )
    return _DEMO_KEY


HMAC_KEY = get_hmac_key()


def escalate(current: str, new: str) -> str:
    """Return the higher of two severities. CRITICAL can never be downgraded."""
    return new if SEVERITY_RANK[new] > SEVERITY_RANK[current] else current


@dataclass
class TelemetryEvent:
    event_id: str
    timestamp: float
    player_id: str
    ip_address: str
    archetype: str
    action: str
    x: float
    y: float
    value_delta: float


def anonymize_pii(raw_value: str, prefix: str, key: Optional[bytes] = None) -> str:
    digest = hmac.new(key or HMAC_KEY, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"{prefix}_{digest}"


def is_bot_cadence(dts: List[float], actions: List[str]) -> Optional[str]:
    """Return a reason string if timing and action mix look automated, else None.

    Uses both absolute spread (stdev) and relative spread (coefficient of
    variation), so a slow but perfectly regular macro is caught too, and a
    short session never gets judged on too little data.
    """
    if len(actions) < BOT_MIN_EVENTS or len(dts) < 2:
        return None
    mean_dt = statistics.mean(dts)
    if mean_dt <= 0:
        return None
    dt_stdev = statistics.stdev(dts)
    cv = dt_stdev / mean_dt
    unique_ratio = len(set(actions)) / len(actions)
    regular = dt_stdev < BOT_MAX_DT_STDEV or cv < BOT_MAX_CV
    if regular and unique_ratio < BOT_MAX_UNIQUE_RATIO:
        return f"bot_cadence(dt_stdev={dt_stdev:.3f}s, cv={cv:.3f}, unique_ratio={unique_ratio:.2f})"
    return None


def build_synthetic_dataset() -> List[TelemetryEvent]:
    events: List[TelemetryEvent] = []
    base_ts = 1763000000.0
    eid = 1

    # Normal players (steady movement, natural pacing, modest ledger deltas)
    for i in range(1, 5):
        pid = f"player_norm_{i:02d}"
        ip = f"198.51.100.{10 + i}"
        t = base_ts
        x, y = 100.0 * i, 50.0 * i
        for step in range(8):
            dt = 1.6 + (step % 3) * 0.45
            t += dt
            x += 4.5 * dt
            y += 2.2 * dt
            action = ["move", "quest_step", "gather", "trade_sync"][step % 4]
            delta = 25.0 if action == "trade_sync" else 5.0
            events.append(TelemetryEvent(f"E{eid:04d}", t, pid, ip, "normal", action, x, y, delta))
            eid += 1

    # Legitimate high-skill players (fast bursts, varied actions, normal economy)
    for i in range(1, 4):
        pid = f"player_skill_{i:02d}"
        ip = f"203.0.113.{20 + i}"
        t = base_ts + 200.0
        x, y = 300.0, 200.0
        for step in range(9):
            dt = 0.55 + (step % 4) * 0.35
            t += dt
            burst = 14.0 if step in (2, 6) else 7.5
            x += burst * dt
            y -= 4.0 * dt
            action = ["dash", "combo_hit", "dodge", "loot", "move"][step % 5]
            delta = 40.0 if action == "loot" else 0.0
            events.append(TelemetryEvent(f"E{eid:04d}", t, pid, ip, "high_skill", action, x, y, delta))
            eid += 1

    # Bot farm (tight rhythmic intervals, repetitive action loop, steady micro-gains)
    for i in range(1, 4):
        pid = f"bot_farm_{i:02d}"
        ip = f"192.0.2.{50 + i}"
        t = base_ts + 500.0
        x, y = 500.0 + i * 10, 600.0
        for step in range(12):
            dt = 1.00 + (0.01 if step % 2 == 0 else -0.01)
            t += dt
            x += 2.0
            action = "farm_node" if step % 5 != 4 else "collect_herb"
            events.append(TelemetryEvent(f"E{eid:04d}", t, pid, ip, "bot_farm", action, x, y, 18.0))
            eid += 1

    # Speed / teleport hacker (impossible coordinate jump over tiny delta time)
    for i in range(1, 3):
        pid = f"speed_hack_{i:02d}"
        ip = f"198.51.100.{90 + i}"
        t = base_ts + 800.0
        x, y = 10.0, 10.0
        for step in range(6):
            dt = 0.5
            t += dt
            if step == 3:
                x += 450.0
                y += 320.0
                action = "teleport_burst"
            else:
                x += 6.0
                y += 3.0
                action = "move"
            events.append(TelemetryEvent(f"E{eid:04d}", t, pid, ip, "speed_hacker", action, x, y, 0.0))
            eid += 1

    # Item / currency duper (extreme ledger delta spike)
    for i in range(1, 3):
        pid = f"item_duper_{i:02d}"
        ip = f"203.0.113.{80 + i}"
        t = base_ts + 1100.0
        x, y = 750.0, 400.0
        for step in range(6):
            dt = 1.2 + step * 0.2
            t += dt
            x += 3.0
            if step == 4:
                delta = 25000.0
                action = "trade_sync_spike"
            else:
                delta = 30.0
                action = "trade_sync"
            events.append(TelemetryEvent(f"E{eid:04d}", t, pid, ip, "item_duper", action, x, y, delta))
            eid += 1

    return events


def init_db(events: List[TelemetryEvent]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE telemetry (
            event_id TEXT PRIMARY KEY,
            timestamp REAL,
            player_id TEXT,
            ip_address TEXT,
            archetype TEXT,
            action TEXT,
            x REAL,
            y REAL,
            value_delta REAL
        )
        """
    )
    conn.executemany(
        "INSERT INTO telemetry VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                e.event_id,
                e.timestamp,
                e.player_id,
                e.ip_address,
                e.archetype,
                e.action,
                e.x,
                e.y,
                e.value_delta,
            )
            for e in events
        ],
    )
    conn.commit()
    return conn


def analyze_players(conn: sqlite3.Connection) -> List[Dict]:
    rows = conn.execute(
        """
        SELECT event_id, timestamp, player_id, ip_address, archetype, action, x, y, value_delta
        FROM telemetry
        ORDER BY player_id, timestamp
        """
    ).fetchall()

    by_player: Dict[str, List[TelemetryEvent]] = {}
    for r in rows:
        ev = TelemetryEvent(*r)
        by_player.setdefault(ev.player_id, []).append(ev)

    return [analyze_player(pid, evs) for pid, evs in sorted(by_player.items())]


def analyze_player(pid: str, evs: List[TelemetryEvent]) -> Dict:
    """Score one player's time-ordered events."""
    actions = [e.action for e in evs]
    dts: List[float] = []
    peak_speed, speed_event = 0.0, None
    for prev, curr in zip(evs, evs[1:]):
        dt = max(curr.timestamp - prev.timestamp, MIN_DT)
        dts.append(dt)
        speed = math.hypot(curr.x - prev.x, curr.y - prev.y) / dt
        if speed > peak_speed:
            peak_speed, speed_event = speed, curr

    value_event = max(evs, key=lambda e: e.value_delta) if evs else None
    max_delta = value_event.value_delta if value_event else 0.0
    total_delta = sum(e.value_delta for e in evs)

    reasons: List[str] = []
    actions_out: List[str] = []
    severity = "CLEAN"
    # The event that triggered the most severe signal; its IP is reported,
    # not simply the player's first event.
    evidence: Optional[TelemetryEvent] = None

    if peak_speed > SPEED_LIMIT_UPS:
        reasons.append(f"peak_speed={peak_speed:.1f}u/s (>{SPEED_LIMIT_UPS})")
        actions_out.append(SUGGESTED_ACTION["speed"])
        severity = escalate(severity, "CRITICAL")
        evidence = evidence or speed_event

    if max_delta >= VALUE_SPIKE:
        reasons.append(f"max_value_delta={max_delta:.0f} (>={VALUE_SPIKE:.0f})")
        actions_out.append(SUGGESTED_ACTION["value"])
        severity = escalate(severity, "CRITICAL")
        evidence = evidence or value_event

    bot_reason = is_bot_cadence(dts, actions)
    if bot_reason:
        reasons.append(bot_reason)
        actions_out.append(SUGGESTED_ACTION["bot"])
        severity = escalate(severity, "HIGH")
        evidence = evidence or evs[-1]

    evidence = evidence or evs[0]
    return {
        "raw_player_id": pid,
        "anon_player_id": anonymize_pii(pid, "plr"),
        "anon_ip": anonymize_pii(evidence.ip_address, "ip"),
        "evidence_event": evidence.event_id,
        "archetype": evs[0].archetype,
        "flagged": bool(reasons),
        "severity": severity,
        "reasons": reasons,
        "actions": actions_out,
        "total_delta": total_delta,
    }


def main() -> None:
    events = build_synthetic_dataset()
    conn = init_db(events)
    findings = analyze_players(conn)

    # Ground-truth evaluation across archetypes (normal and high_skill should stay clean)
    malicious_archetypes = {"bot_farm", "speed_hacker", "item_duper"}
    tp = sum(1 for f in findings if f["flagged"] and f["archetype"] in malicious_archetypes)
    fp = sum(1 for f in findings if f["flagged"] and f["archetype"] not in malicious_archetypes)
    fn = sum(1 for f in findings if not f["flagged"] and f["archetype"] in malicious_archetypes)

    recall = tp / max(tp + fn, 1) * 100.0
    precision = tp / max(tp + fp, 1) * 100.0

    print("AEGIS LOG SENTINEL | ZERO-LEAK GAME SECURITY TRIAGE BRIEF")
    print("=" * 60)
    print(
        f"Events: {len(events)} | Players: {len(findings)} | "
        f"Recall: {recall:.1f}% | Precision: {precision:.1f}% | False Positives: {fp}"
    )
    print("-" * 60)

    flagged = [f for f in findings if f["flagged"]]
    flagged.sort(key=lambda f: -SEVERITY_RANK[f["severity"]])
    for f in flagged:
        reason_str = "; ".join(f["reasons"])
        print(
            f"[{f['severity']}] {f['anon_player_id']} ({f['anon_ip']}, event {f['evidence_event']}) "
            f"-> {reason_str} | net_delta={f['total_delta']:.0f}"
        )
        print(f"    action: {' + '.join(f['actions'])}")


if __name__ == "__main__":
    main()
