import hashlib
import hmac
import math
import sqlite3
import statistics
from dataclasses import dataclass
from typing import Dict, List, Tuple


HMAC_KEY = b"aegis-local-triage-key-v1"


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


def anonymize_pii(raw_value: str, prefix: str) -> str:
    digest = hmac.new(HMAC_KEY, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"{prefix}_{digest}"


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

    findings = []
    for pid, evs in sorted(by_player.items()):
        speeds = []
        dts = []
        max_delta = 0.0
        total_delta = 0.0
        actions = [e.action for e in evs]

        for prev, curr in zip(evs, evs[1:]):
            dt = max(curr.timestamp - prev.timestamp, 1e-3)
            dist = math.hypot(curr.x - prev.x, curr.y - prev.y)
            speeds.append(dist / dt)
            dts.append(dt)

        for e in evs:
            max_delta = max(max_delta, e.value_delta)
            total_delta += e.value_delta

        peak_speed = max(speeds) if speeds else 0.0
        dt_stdev = statistics.stdev(dts) if len(dts) >= 2 else 1.0
        unique_ratio = len(set(actions)) / max(len(actions), 1)

        reasons = []
        severity = None

        if peak_speed > 120.0:
            reasons.append(f"peak_speed={peak_speed:.1f}u/s (>120.0)")
            severity = "CRITICAL"

        if max_delta >= 5000.0:
            reasons.append(f"max_value_delta={max_delta:.0f} (>=5000)")
            severity = "CRITICAL"

        if len(evs) >= 10 and dt_stdev < 0.05 and unique_ratio < 0.25:
            reasons.append(
                f"bot_cadence(dt_stdev={dt_stdev:.3f}s, unique_ratio={unique_ratio:.2f})"
            )
            if severity != "CRITICAL":
                severity = "HIGH"

        flagged = bool(reasons)
        findings.append(
            {
                "raw_player_id": pid,
                "anon_player_id": anonymize_pii(pid, "plr"),
                "anon_ip": anonymize_pii(evs[0].ip_address, "ip"),
                "archetype": evs[0].archetype,
                "flagged": flagged,
                "severity": severity or "CLEAN",
                "reasons": reasons,
                "total_delta": total_delta,
            }
        )

    return findings


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

    for f in findings:
        if f["flagged"]:
            reason_str = "; ".join(f["reasons"])
            print(
                f"[{f['severity']}] {f['anon_player_id']} ({f['anon_ip']}) "
                f"-> {reason_str} | net_delta={f['total_delta']:.0f}"
            )


if __name__ == "__main__":
    main()
