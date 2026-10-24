# CLAUDE.md — AgentWall project context (read this first)

You are continuing **AgentWall**, a web/HTTP-layer detect-and-report system for
rogue AI-agent attacks, built with Grug (independent security researcher, SEQ
QLD, sole trader). This file bootstraps a fresh session — the prior work
happened in another conversation whose transcript you do NOT have. Trust the
code and the docs here over any assumption.

## What it is
Detects the behaviour from the two 2026 incidents:
- **Medicare (Jun 2026):** agent blocked → found workarounds → read non-public
  files → wrote to server. → `block_defiance`.
- **Hugging Face (Jul 2026):** malicious dataset / indirect prompt injection,
  C2 + exfil on ordinary public services. → `injection_tripwire` + `egress_deaddrop`.

Positioning (decided): NOT a standalone "AI defence" platform — a feature-plus-
service sold through MSPs, anchored to the ACSC 25 Sep 2026 High alert. Sell the
outcome + ACSC-ready evidence pack, never fear. Read `METHODOLOGY.md` and
`README.md` for the full write-up and the competitive landscape rationale.

## Run / test (everything is Python 3 stdlib, no deps)
```
python3 eval.py            # 10-seed session-level eval (headline numbers)
python3 stress.py          # hard benign traffic, expect 0 FP
python3 stress_nat.py      # NAT /24 FP gate + actor-scoped cross-session recall
python3 unit_checks.py     # proves each of the 6 additions fires (+ correlator streaming)
python3 cross_tenant_demo.py  # the moat: distributed-swarm correlation
python3 honeypot_drive.py  # live server + real HTTP + detectors (end-to-end)
python3 ingest.py LOG      # run detectors on real nginx/Cloudflare/JSONL logs
python3 analyze.py LOG     # summarise + score any honeypot/access log
```

## Current state (all green; do not regress)
- eval: recall 98.9% ±1.5%, precision 100%, FPR 0.0%
- stress: 0 FP / 6300 benign · stress_nat: 3/3 + cross-session 200/200
- unit_checks: 9/9 · honeypot e2e: 54 real requests → 5 detections, 0 benign FP

## Files
- `events.py` — `Event` / `Detection` data model. **Invariant: detectors must
  NEVER read `Event.truth`** (ground truth is for the eval harness only).
- `detectors.py` — 4 detectors: `block_defiance` (fast per-session + slow
  per-actor/24 scope), `injection_tripwire` (canary + denial-page nonce proof +
  LLM-artifact), `egress_deaddrop`, `kill_chain`.
- `correlation.py` — cross-tenant swarm correlation (the moat), two tiers
  (grammar+shape, grammar-only), privacy-preserving digests only.
- `simulator.py` — labelled traffic (humans/goodbots/egress + 3 attack vectors).
- `eval.py` / `stress.py` / `stress_nat.py` / `unit_checks.py` / `cross_tenant_demo.py` — tests.
- `ingest.py` / `analyze.py` — real-log tooling.
- `honeypot.py` (+ `honeypot_drive.py`) — live decoy server, XFF-aware.
- `Dockerfile` / `docker-compose.yml` / `agentwall-honeypot.service` / `DEPLOY.md` — deploy.

## Hardening log (bugs the testing caught — don't reintroduce)
1. Normaliser fragmented evasion variants across resource keys → 18.5% recall.
   Fixed: `_resource_key` collapses case/encoding/dot-seg/trailing/version.
2. Breakthrough write to a CHILD path didn't match the denied parent. Fixed:
   parent/child matching in `_find_armed`.
3. **NAT /24 false positive**: slow (actor) scope stitched many humans behind
   one office IP + 1 legit login into a fake block-defiance. Fixed: slow scope
   requires real evasion grammar (≥N distinct variants AND a HARD_EVASION
   class), never attempt volume. Gated by `stress_nat.py` — keep it passing.

## Invariants / design rules
- Detect-and-report only. **No enforcement, no hacking back** (Criminal Code
  Part 10.7). Honeypot is passive; decoys are inert and labelled TEST-ONLY.
- Keep precision at 100% / FPR 0 on the benign + NAT suites. If a new detector
  trades FP for recall, gate it behind a test and say so.
- Metrics are simulation + a loopback end-to-end run. Real public traffic via
  `DEPLOY.md` is the outstanding validation step; don't oversell sim numbers.

## Open threads (pick up here)
- Correlator transport/auth: tenants POST signals over TLS; currently in-process.
- Enforcement hooks (Cloudflare/Entra/firewall API) — deliberately not built.
- `docker build` was never run in the origin env (locked egress) — build it.
- Real-traffic collection: deploy honeypot behind Cloudflare Tunnel / VPS.
- Business side: MSP pricing, the ACSC-anchored pitch, demand validation.
