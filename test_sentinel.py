"""Unit tests for Aegis Log Sentinel. Run: python3 -m unittest -v"""
import os
import unittest
from unittest import mock

os.environ.setdefault("AEGIS_HMAC_KEY", "test-key")  # keep the demo-key warning out of test output

import sentinel
from sentinel import TelemetryEvent, analyze_player, escalate, is_bot_cadence


def ev(i, t, x=0.0, y=0.0, action="move", delta=0.0, ip="10.0.0.1", pid="p1", arch="test"):
    return TelemetryEvent(f"E{i:04d}", t, pid, ip, arch, action, x, y, delta)


class TestSeverity(unittest.TestCase):
    def test_critical_never_downgraded(self):
        self.assertEqual(escalate("CRITICAL", "HIGH"), "CRITICAL")
        self.assertEqual(escalate("CRITICAL", "CLEAN"), "CRITICAL")

    def test_escalates_up(self):
        self.assertEqual(escalate("CLEAN", "HIGH"), "HIGH")
        self.assertEqual(escalate("HIGH", "CRITICAL"), "CRITICAL")

    def test_speed_plus_bot_stays_critical(self):
        # Regular bot loop that also teleports once: bot check runs last and must not downgrade.
        evs = [ev(i, 1.0 * i, x=2.0 * i, action="farm_node") for i in range(12)]
        evs[6] = ev(6, 6.0, x=900.0, action="farm_node")
        f = analyze_player("p1", evs)
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(len(f["reasons"]), 2)


class TestPseudonymization(unittest.TestCase):
    def test_deterministic_and_hides_raw(self):
        a = sentinel.anonymize_pii("player_42", "plr", key=b"k1")
        self.assertEqual(a, sentinel.anonymize_pii("player_42", "plr", key=b"k1"))
        self.assertNotIn("player_42", a)
        self.assertTrue(a.startswith("plr_"))

    def test_key_changes_output(self):
        self.assertNotEqual(
            sentinel.anonymize_pii("player_42", "plr", key=b"k1"),
            sentinel.anonymize_pii("player_42", "plr", key=b"k2"),
        )

    def test_key_read_from_env(self):
        with mock.patch.dict(os.environ, {"AEGIS_HMAC_KEY": "from-env"}):
            self.assertEqual(sentinel.get_hmac_key(), b"from-env")

    def test_no_hardcoded_production_key(self):
        with open(sentinel.__file__, encoding="utf-8") as fh:
            self.assertNotIn("aegis-local-triage-key-v1", fh.read())


class TestEvidenceIP(unittest.TestCase):
    def test_reports_ip_of_offending_event(self):
        evs = [ev(i, 1.0 + i, x=float(i), ip="1.1.1.1") for i in range(5)]
        evs.append(ev(5, 6.0, x=5000.0, ip="9.9.9.9"))  # teleport from a new IP
        f = analyze_player("p1", evs)
        self.assertEqual(f["evidence_event"], "E0005")
        self.assertEqual(f["anon_ip"], sentinel.anonymize_pii("9.9.9.9", "ip"))

    def test_value_spike_evidence(self):
        evs = [ev(i, 1.0 + i, delta=10.0, ip="1.1.1.1") for i in range(4)]
        evs.append(ev(4, 6.0, delta=25000.0, ip="8.8.8.8"))
        f = analyze_player("p1", evs)
        self.assertEqual(f["evidence_event"], "E0004")
        self.assertEqual(f["severity"], "CRITICAL")


class TestBotCadence(unittest.TestCase):
    def test_too_few_events_not_judged(self):
        self.assertIsNone(is_bot_cadence([1.0] * 5, ["farm"] * 6))

    def test_single_gap_not_judged(self):
        self.assertIsNone(is_bot_cadence([1.0], ["farm"] * 10))

    def test_tight_loop_flagged(self):
        self.assertIsNotNone(is_bot_cadence([1.0, 1.01, 0.99] * 4, ["farm"] * 13))

    def test_slow_regular_macro_flagged(self):
        # 30s gaps with 0.3s jitter: stdev is large in seconds, but cv = 1%.
        dts = [30.0 + (0.3 if i % 2 else -0.3) for i in range(12)]
        self.assertIsNotNone(is_bot_cadence(dts, ["farm"] * 13))

    def test_regular_but_varied_actions_clean(self):
        actions = ["a", "b", "c", "d", "e"] * 3
        self.assertIsNone(is_bot_cadence([1.0] * 14, actions))

    def test_human_jitter_clean(self):
        dts = [0.6, 1.9, 0.8, 2.4, 1.1, 0.7, 3.0, 1.5, 0.9, 2.2, 1.3]
        self.assertIsNone(is_bot_cadence(dts, ["farm"] * 12))

    def test_duplicate_timestamps_no_crash(self):
        evs = [ev(i, 100.0, action="farm") for i in range(12)]
        f = analyze_player("p1", evs)
        self.assertIn(f["severity"], ("CLEAN", "HIGH"))


class TestBaseline(unittest.TestCase):
    def test_synthetic_baseline_perfect(self):
        conn = sentinel.init_db(sentinel.build_synthetic_dataset())
        findings = sentinel.analyze_players(conn)
        bad = {"bot_farm", "speed_hacker", "item_duper"}
        for f in findings:
            self.assertEqual(f["flagged"], f["archetype"] in bad, f["raw_player_id"])

    def test_high_skill_never_flagged(self):
        conn = sentinel.init_db(sentinel.build_synthetic_dataset())
        for f in sentinel.analyze_players(conn):
            if f["archetype"] == "high_skill":
                self.assertEqual(f["severity"], "CLEAN")


if __name__ == "__main__":
    unittest.main()
