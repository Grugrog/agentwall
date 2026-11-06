# CLAUDE.md — AgentWall project context (read this first)

You are continuing **AgentWall**, a web/HTTP-layer detect-and-report system for
rogue AI-agent attacks, built with Grug (independent security researcher, SEQ
QLD, sole trader). This file bootstraps a fresh session — trust the code and
docs here over any assumption.

## What it is
Detects the behaviour from the two 2026 incidents:
- **Medicare (Jun 2026):** agent blocked → found workarounds → read non-public
  files → wrote to server. → `block_defiance`.
- **Hugging Face (Jul 2026):** malicious dataset / indirect prompt injection,
  C2 + exfil on ordinary public services. → `injection_tripwire` + `egress_deaddrop`.

Positioning (decided): NOT a standalone "AI defence" platform — a feature-plus-
service sold through MSPs, anchored to the ACSC 25 Sep 2026 High alert. Sell the
outcome + ACSC-ready evidence pack, never fear. See `METHODOLOGY.md`,
`COMPETITIVE_LANDSCAPE.md`, `ROADMAP.md`.

## Run / test (Python 3 stdlib, no deps) — all currently PASS
```
python3 eval.py            # 98.2% recall / 100% precision / 0 FP (10 seeds)
python3 stress.py          # 0 FP across 6300 hard-benign sessions
python3 stress_nat.py      # NAT /24 FP gate 3/3 + cross-session recall 200/200
python3 unit_checks.py     # each of the 6 additions fires: 8/8
python3 cross_tenant_demo.py   # distributed-swarm correlation (the moat)
python3 honeypot_drive.py  # live server + real HTTP + detectors (54 → 5)
python3 ingest.py LOG      # run detectors on real nginx/Cloudflare/JSONL logs
python3 ingest.py tests/real_log_fp/<case>.log   # real-log FP regression
```

## Files
- `events.py` — `Event`/`Detection` model. **Invariant: detectors NEVER read `Event.truth`.**
- `detectors.py` — 4 detectors: `block_defiance` (fast per-session + slow per-actor/24),
  `injection_tripwire` (canary + denial-page nonce proof + LLM-artifact),
  `egress_deaddrop`, `kill_chain`.
- `correlation.py` — cross-tenant swarm correlation (the moat), two tiers.
- `simulator.py` — labelled traffic. `eval.py`/`stress.py`/`stress_nat.py`/
  `unit_checks.py`/`cross_tenant_demo.py` — tests. `ingest.py`/`analyze.py` — real-log tooling.
- `honeypot.py` (+ `honeypot_drive.py`) — live decoy server, XFF-aware.
- `Dockerfile`/`docker-compose.yml`/`agentwall-honeypot.service`/`DEPLOY.md` — deploy.
- `patches/` — `agentwall-fp-fix.patch` and `events-fields-fix.patch` are **already
  applied** in this tree; kept for the record.
- `tests/real_log_fp/` — real nginx-format FP regression (a,b → 0 ; c,d → 1).

## Hardening log (bugs the testing caught — don't reintroduce)
1. Normaliser fragmented evasion variants across resource keys → 18.5% recall. Fixed.
2. Breakthrough write to a CHILD path didn't match the denied parent. Fixed.
3. **NAT /24 FP**: slow scope stitched many humans behind one IP + 1 legit login into
   a fake alert. Fixed: slow scope requires real evasion grammar, not volume. Gated by `stress_nat.py`.
4. **events.py drift**: an older `events.py` lacked `denial_nonce` / `actor_type` /
   `signature` / `confidence`, crashing every run. Fixed (`patches/events-fields-fix.patch`).
5. **Legit re-auth misread**: a same-path 2xx after a deny (token refresh) was read as a
   breakthrough. Fixed (`patches/agentwall-fp-fix.patch`); `tests/real_log_fp/` guards it.

## Invariants / design rules
- Detect-and-report only. **No enforcement, no hacking back** (Criminal Code Part 10.7).
  Honeypot is passive; decoys inert and labelled TEST-ONLY.
- Keep precision 100% / FPR 0 on the benign + NAT + real-log suites. Gate any new detector.
- Metrics are simulation + a loopback end-to-end run. Real public traffic (see `DEPLOY.md`)
  is the outstanding validation step; don't oversell sim numbers.

## Open threads
- Correlator transport/auth (tenants POST signals over TLS) — in-process only.
- Enforcement hooks (Cloudflare/Entra/firewall API) — deliberately not built.
- Real-traffic collection: deploy honeypot behind Cloudflare Tunnel / VPS.
- Business: MSP pricing, the ACSC-anchored pitch, demand validation.
