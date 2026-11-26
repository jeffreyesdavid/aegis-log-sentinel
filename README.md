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
python3 -m unittest -v                    # 27 tests
```

The pseudonymization key is read from `AEGIS_HMAC_KEY` and never stored in source. Without it, the demo runs on a clearly labeled demo key and prints a warning.

---

## AI Bot Detection Layer (v1.2)

**The problem:** a smarter bot adds random jitter to every delay (for example 0.75–1.25 s). Its timing spread now looks human, so the v1.1 cadence rule misses it. In the benchmark, v1.1 rules alone caught **0 of 4** of these "smart bots."

**The fix:** an unsupervised second opinion that learns what normal looks like from the player population itself, with no labeled cheat data required.

| Step | What it does |
|---|---|
| Behavioral features | Per player: timing spread (CV), slow-vs-fast gap ratio (log p90/p10), action-loop repetition, next-action predictability |
| Isolation Forest | Standard-library implementation of Liu, Ting & Zhou (2008). Random cuts isolate unusual players in fewer steps; small subsamples (8 per tree) prevent a group of similar bots from hiding together ("masking") |
| Explanation | Each flag names the features furthest from the crowd, e.g. `action loop repetition 1.00 vs crowd 0.36` |
| Human in the loop | AI flags go to a `REVIEW` queue for session-replay checks. The AI never bans and never lowers a rule-based severity |

**Why these features:** humans mix quick clicks with real pauses, so their slow-vs-fast gap ratio is wide; a bot drawing "random" delays from a fixed window cannot pause. Humans who grind the same node still do it in a messy order; a script repeats an exact loop.

**Results (synthetic data):** tuned on 8 random worlds, then tested on 10 worlds never seen during tuning: **110 of 110 cheaters flagged, 0 of 470 legitimate players flagged**, including 100 "grinders" who farm repetitively on purpose.

**Limits, stated plainly:** all data is synthetic, and the human/bot score margin is narrow (about 0.58 vs 0.60), so thresholds would need recalibration on real telemetry. Real deployments group players by play style before modeling, as in Chung et al. (2015), and add signals this demo lacks: movement paths, social and trade graphs, and network patterns.

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

