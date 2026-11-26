# Aegis Log Sentinel

**Zero-Leak Live-Service Game Telemetry & Exploit Triage Engine**

Aegis Log Sentinel is a lightweight game security investigation and triage pipeline modeled for live-service MMO and action titles. It demonstrates how security analysts can safely pair deterministic behavioral detection with AI-assisted reporting without exposing player PII or confidential game telemetry to external tools.

---

## Key Capabilities

1. **Zero-Leak PII Guardrail (`anonymize_pii`)**
   - Enforces one-way HMAC-SHA256 pseudonymization on raw player IDs and IP addresses before any telemetry cluster is packaged for external LLM summarization or cross-team reporting.
2. **Multi-Vector Cheat & Abuse Detection**
   - **Movement Physics & Teleportation:** Evaluates coordinate deltas over elapsed time (`units/sec`) to catch speed hacks and blink/warp exploits while filtering out legitimate high-skill movement bursts.
   - **2027 "Agentic" & Macro Bot Cadence:** Measures inter-action timing variance (`dt_stdev`) and action diversity ratios to isolate automated farming loops with low behavioral entropy.
   - **Economy & Currency Duplication:** Flags abnormal single-transaction currency injections and net ledger anomalies for rapid trade freezes and rollback audits.
3. **False-Positive Stress Testing**
   - Benchmarks detection rules against a dedicated cohort of legitimate `high_skill` players alongside `normal`, `bot_farm`, `speed_hacker`, and `item_duper` archetypes (`100% Recall | 100% Precision | 0 False Positives` on baseline seed).
4. **Producer-Ready Triage Briefs**
   - Translates raw packet and ledger anomalies into prioritized severity levels (`CRITICAL` / `HIGH`) with concrete operational actions (suspension, trade freeze, packet log capture).

---

## Quickstart

Requires Python 3.10+ (uses only the Python standard library: `sqlite3`, `hashlib`, `hmac`, `statistics`, `math`).

```bash
export AEGIS_HMAC_KEY="your-own-secret"   # optional for the demo; required for real telemetry
python3 sentinel.py
python3 -m unittest -v                    # 18 tests
```

The pseudonymization key is read from `AEGIS_HMAC_KEY` and never stored in source. Without it, the demo runs on a clearly labeled demo key and prints a warning.

---

## Hardening (v1.1)

Fixes from a self-audit of v1:

| Issue | Fix |
|---|---|
| Severity was set by plain assignment, so a future check could downgrade a `CRITICAL` | `escalate()` with a severity rank: findings can only go up, never down |
| HMAC key hardcoded in source | Key loaded from the `AEGIS_HMAC_KEY` environment variable |
| Reported IP was the player's first event, not the event that triggered the alert | Each finding records the evidence event and pseudonymizes that event's IP |
| Bot cadence judged only on absolute timing spread | Adds a coefficient-of-variation check (catches slow but perfectly regular macros) and refuses to judge sessions with too little data |
| No automated tests | 18 `unittest` cases: severity, pseudonymization, evidence IP, bot edge cases, and the false-positive baseline |

Every flagged finding now prints a suggested analyst action (suspend and capture logs, freeze trades and audit, or bot review). Actions are recommendations: a human makes the final call.

