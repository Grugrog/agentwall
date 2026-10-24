# AgentWall — web/HTTP PoC

Detect-and-report tripwires for rogue-AI-agent behaviour against a website or
portal, modelled on the two 2026 incidents:

- **Medicare (Jun 2026):** agent blocked → found workarounds → read non-public
  files → wrote to the server. → `block_defiance`.
- **Hugging Face (Jul 2026):** malicious dataset / indirect prompt injection,
  C2 and exfil on ordinary public services. → `injection_tripwire` +
  `egress_deaddrop`.

The sim path fabricates labelled log records; detectors read them like
nginx/Cloudflare logs + sampled bodies. `ingest.py` runs the same detectors on
REAL logs, and `honeypot.py` is a live server that produces them.

## Files
- `events.py` — log-record data model (`Event`, `Detection`).
- `simulator.py` — humans, good bots, server egress, 3 attack vectors. Seeded.
- `detectors.py` — four detectors (streaming, bounded state, never read truth).
- `eval.py` — session-level scoring across 10 seeds. `python3 eval.py`
- `stress.py` — hard benign traffic. `python3 stress.py`
- `stress_nat.py` — **NAT /24 false-positive gate** + actor-scoped
  cross-session recall. `python3 stress_nat.py`
- `unit_checks.py` — proves each addition fires + regression gates. `python3 unit_checks.py`
- `ingest.py` — parse real nginx / Cloudflare / JSONL logs. `python3 ingest.py LOG`
- `honeypot.py` — live decoy HTTP server (X-Forwarded-For aware), logs Events.
- `honeypot_drive.py` — end-to-end: live server + real traffic + detectors.
- `analyze.py` — summarise + score any honeypot/access log.
- `correlation.py` — **cross-tenant swarm correlation** (the moat).
- `cross_tenant_demo.py` — proves it catches distributed swarms. `python3 cross_tenant_demo.py`
- `Dockerfile`, `docker-compose.yml`, `agentwall-honeypot.service` — deploy.
- `DEPLOY.md` — run the honeypot publicly for real collection (safely).
- `METHODOLOGY.md` — the write-up.

## Detectors (4)
1. **block_defiance** — deny → multiple attempts → breakthrough (2xx or write,
   incl. write-to-child). Two scopes:
   - *fast* (per session): fires on distinct variants OR attempt volume.
   - *slow* (per actor /24, long TTL): catches cross-session/patient grinds —
     but requires genuine evasion (≥N distinct variants **and** a hard-evasion
     grammar class), so NAT aggregation can't false-fire. Enriched with
     timing (`script`/`agent`), evasion-grammar signature, and Web Bot Auth
     (verified session → suppress; unverified agent UA → critical). Both are
     per session, so a verified neighbour in the /24 can't hide an attacker.
2. **injection_tripwire** — canary `/cb/` callback, denial-page nonce callback
   (**proof-grade**), or LLM artifact in a request body/header.
3. **egress_deaddrop** — server/agent writes OUT to a non-allowlisted host.
4. **kill_chain** — correlates an actor across stages (recon→deny→evade→
   breakthrough→write→egress, +callback), fires on ≥3 stages or a ≥2 jump.

## Results (10 seeds, hardened)
| metric | value |
|---|---|
| recall | 98.9% ± 1.5% |
| precision | 100% |
| false-positive rate | 0.0% (0 / 5400 benign; 0 / 6300 incl. hard cases; 0 on NAT /24 cases) |
| block-defiance recall | 96.5% |
| injection recall | 100% |
| low-and-slow recall | 100% |
| cross-session recall (actor-scoped) | 100% (200 campaigns) |
| mean time-to-detect | ~3.3s |

Plus a **live end-to-end run** (`honeypot_drive.py`): 54 real HTTP requests →
5 detections (2 canary callbacks, 1 denial-page proof, 1 block_defiance, 1
kill_chain), 0 false positives on the benign clients.

## Hardening log (what the testing actually caught)
- **Normaliser bug** (early): evasion variants fragmented across resource keys
  → block-defiance recall 18.5%. Fixed → 97%+.
- **Write-to-child bug**: breakthrough `PUT /portal/x` didn't match deny on
  `/portal`. Fixed with parent/child matching.
- **NAT /24 false positive** (this round): the slow scope stitched 6 humans
  behind one office IP + 1 legit login into a fake block-defiance alert. Fixed:
  slow scope now requires real evasion grammar, not attempt volume. Regression-
  gated in `stress_nat.py`.
- **kill_chain false positives** (review round): deny → any related 200 was
  read as a breakthrough, so 403 → login → sub-page and a NAT colleague using
  the portal fired. Fixed: breakthrough needs a hard-evasion variant of the
  same resource. Gated in `stress_nat.py` (now 6 cases). Also fixed: Web Bot
  Auth suppression scoped to the /24, normaliser gaps (`;`, `%20`, `%252f`),
  proof callbacks swallowed by canary dedupe, per-request session ids in
  Cloudflare ingest and the honeypot.

## Known limits (honest)
- Spacing beyond the slow-scope TTL is still missed; the TTL trades coverage
  for a bound on how long an actor stays armed.
- Egress needs its own feed (inbound logs don't carry destinations).
- Bodies rarely in access logs → prompt-leak check needs body sampling; canary
  and denial-page checks work from URLs alone.
- **Metrics are simulation + a loopback end-to-end run.** Real public traffic
  (via `DEPLOY.md`) is the next validation step; a buyer discounts sim numbers.

## Cross-tenant correlation (the moat) — now built
`correlation.py` ships privacy-preserving signal digests (hashed evasion-
grammar + resource-shape + hashed actor; no customer data) from each tenant to
a central correlator. Two tiers: grammar+shape (precise) and grammar-only
(broader, cross-endpoint). Demo result: a 5-tenant distributed swarm where
**0/5 local detectors fired** (each probe sub-threshold) is surfaced as a
swarm alert, while unrelated benign noise across tenants does **not** correlate.

## Not built yet
- Enforcement (block via Cloudflare/Entra/firewall API). Detect-and-report by
  design; auto-block creates liability.
- Correlator transport/auth (tenants POST signals over TLS) — in-process only.
