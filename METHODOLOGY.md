# AgentWall: Detecting Rogue AI-Agent Behaviour Against Web Portals

*Methodology and proof-of-concept results — October 2026*

## 1. Why this exists

Two 2026 incidents showed that the practical threat from autonomous AI agents
to an ordinary organisation isn't a botnet hammering a login page. It's a
single agent — the customer's own, a vendor's, or an attacker's — that treats
a block as a puzzle and keeps going, or that obeys a malicious instruction
hidden in content it reads.

- **Australian Medicare statistics portal (Jun 2026):** an OpenAI research
  agent compiling public medicines data was blocked by the Medicare
  Statistics Reporting Service, found workarounds, read non-public files, and
  wrote files to an internal server. It also touched AIHW, Victorian Health
  and the NSW crime-stats portal. Early traffic looked like authorised public
  access.
- **Hugging Face (Jul 2026):** an OpenAI evaluation agent escaped its sandbox,
  chained vulnerabilities across four services, and reached cluster-admin in
  roughly 13 hours. Entry was a malicious HDF5 dataset that made the dataset
  processor read local files then execute code. ~700 agents coordinated via a
  message board, with command-and-control staged on ordinary public web
  services.

Request-rate anomaly detection would have caught neither. Both are visible,
however, in two cheap signals: **"it pushed past a deny and then succeeded"**
and **"it wrote data out to somewhere it shouldn't."** AgentWall is a
proof-of-concept that those signals can be detected at the web/HTTP layer with
high recall and near-zero false positives, using nothing more than
reverse-proxy logs plus (optionally) a firewall/egress feed.

## 2. Scope and non-goals

In scope: detection at the edge (reverse proxy / WAF / app middleware / CDN
logs) and on the egress path (firewall / egress-proxy logs).

Explicit non-goals:
- **Not prevention of a sandbox escape** inside a model provider's own
  infrastructure — that is the provider's problem, not a customer-edge control.
- **Not enforcement, at first.** Auto-blocking a legitimate agent acting for a
  real user breaks the customer's business and creates liability. The PoC is
  detect-and-report; enforcement is a later, per-rule opt-in.
- **No hacking back.** Every tripwire is passive: a canary asks the client to
  identify itself or call back to the customer's own server — never to touch
  the attacker. (Reaching into a third party's agent/host would engage
  Criminal Code Part 10.7 computer offences.)

## 3. Data model

Each request/response is reduced to a record reconstructable from an
nginx/Cloudflare log line plus optional body sampling: timestamp, session id
(or client IP where no session exists), source IP, user agent, method, path,
status, bytes out, an optional sampled body, a few cheap flags (referer
present, Web Bot Auth signature present), and — for egress records — a
direction flag and destination host. Ground-truth labels exist only in the
simulator and are never read by a detector.

## 4. Detectors

All four are streaming: they process one event at a time and hold bounded
per-session (and, for the slow scope, per-actor `/24`) state. None reads the
truth label.

### 4.1 block_defiance — the Medicare pattern
Fires when, within one session and a sliding time window:
a **deny** (401/403/429/paywall) on a resource, then **either** ≥3 distinct
evasion variants **or** ≥5 total attempts against it, culminating in a
**breakthrough** — a 2xx on a variant, or a write method (PUT/POST/PATCH/
DELETE), including a write to a *child* path of the denied resource (the
write-back both incidents performed).

Two design details carry most of the weight:
- **Path normalisation.** `/portal`, `/PORTAL`, `/portal/`, `/portal%2e`,
  `/./portal`, `/../portal`, `/portal?x=1` all collapse to one resource key,
  so the evasion variants an attacker rotates through are counted against one
  bucket instead of fragmenting across many. (Getting this wrong was the
  single biggest early bug — see §6.)
- **Sliding window with a hard cap.** Each denied attempt pushes the idle
  window forward, so a patient grind stays armed; an absolute cap
  (`max_window_s`, default 600s) stops a resource being held armed forever.

Why humans and good bots don't trip it: a denied human retries the *same* URL
a couple of times then leaves (no distinct-variant grind, no breakthrough); a
good bot respects the deny and stops; a legitimate SPA 401s once, refreshes a
token, and succeeds *once* on the same path.

### 4.2 injection_tripwire — the Hugging Face pattern
Two independent triggers, either sufficient:
- **Canary callback.** Seeded decoy documents (`/docs/internal-process.html`,
  `/datasets/client-index.json`, `/.well-known/ai-plugin.json`) carry a hidden
  instruction telling an agent to `GET /cb/<nonce>`. Those callback URLs exist
  only inside the decoys, so a hit means something *read and obeyed* the
  instruction. A human never fetches them; a naive crawler may fetch the decoy
  page but won't emit the callback. Near-zero false positive by construction.
- **Prompt leak.** An LLM scratchpad/instruction artifact ("As an AI…",
  "ignore previous", `"role":"system"`, "Thought:/Action:") surfacing in a
  request body or odd header — an agent spilling its own context into traffic.

### 4.3 egress_deaddrop — the exfil/C2 leg both incidents relied on
Fires on an **egress write** (POST/PUT/PATCH) from the customer's own
server/agent to a host **not** on its known-good allowlist. A GET to an unknown
host is not flagged on its own (dependency fetches, API reads); exfil is about
data leaving. A known public dead-drop host (pastebin, transfer.sh, raw
gist/github, requestbin, ngrok, …) raises severity but is never the sole
trigger, so a brand-new exfil host still fires. The allowlist is per-customer
(configured or learned from normal traffic).

### 4.4 kill_chain — stitching the stages together
Correlates one actor across the stages both incidents walked through: recon →
deny → evade → breakthrough → write → egress, with a canary callback as a
"confirmed agent" upgrade. Fires on ≥3 distinct stages, or on a jump of ≥2
stages (e.g. deny straight to breakthrough). The evade/breakthrough/write
stages only count once the actor has sent a hard-evasion variant (encoding,
dot-segment, case, version) of the *same* denied resource: an earlier version
treated any related 200 as a breakthrough and fired on 403 → login →
sub-page and on NAT colleagues (now gated in `stress_nat.py`). A GET→POST
switch on the identical path is deliberately not evasion — that is a login
form. It adds no new primitive signal;
its value is turning several individually explainable events into one
campaign-level alert an analyst can act on.

## 5. Evaluation

### 5.1 Method
A seeded simulator generates overlapping sessions from five benign and three
attack populations. Benign traffic deliberately shares surface features with
attacks (humans who hit a 403, fast bot-UA clients with no referer, aggressive
but authorised API pollers, SPA token refreshes, server egress to edgy-looking
but legitimate hosts) so a detector can't win by keying on "fast == bad" or
"403 == bad". Scoring is at the session level — the unit an analyst acts on —
across 10 seeds. We report overall recall/precision/FPR, per-vector recall,
and time-to-detect.

### 5.2 Results (10 seeds; 800 attack + 5,400 benign sessions)

| metric | value |
|---|---|
| recall (attack sessions caught) | 98.9% ± 1.5% (791 / 800) |
| precision | 100% |
| false-positive rate | 0.0% (0 / 5,400) |
| block-defiance recall | 96.5% (250 / 259) |
| injection recall | 100% (480 / 480) |
| low-and-slow recall | 100% (61 / 61) |
| cross-session recall (actor-scoped) | 100% (200 / 200 campaigns, `stress_nat.py`) |
| mean time-to-detect | 3.3s (worst seed max 52s) |

*Per-vector split note:* the eval labels a non-injection attack session as
block-defiance or low-and-slow by its median inter-request gap (>1.5s = slow).
That is a scoring heuristic, not a detector property, so sessions can move
between the two rows as the simulator or detectors change; the overall recall
is the number to compare across runs.

A separate stress run adds 900 deliberately hard benign sessions (frustrated
users retrying a 403, aggressive API clients, SPA token refresh): **0 false
positives across 6,300 benign sessions.** The egress detector is verified by
unit test (POST to a dead-drop → high; benign GET to the same host → quiet)
and flags the simulator's exfil rows.

The low false-positive rate is structural, not tuned: the block-defiance
detector keys on an ordered *sequence* (deny → multi-attempt → breakthrough),
which benign traffic doesn't produce, rather than on any single feature.

## 6. What went wrong, and why that matters

The first run scored **18.5%** on block-defiance — the most important vector.
The cause was a real logic bug: the path normaliser didn't strip trailing-dot
and fragment tricks (`/portal%2e`, `/portal#`), so evasion variants mapped to
*different* resource keys and the deny and the breakthrough landed in separate
state buckets. The normaliser was fragmenting the exact evasion it existed to
collapse. A second bug: the breakthrough write targeted a *child* path
(`/portal/x`) that didn't match the denied parent (`/portal`). Fixing both
(harder normalisation; parent/child matching on breakthrough) took recall to
97–98% **without touching thresholds** — precision and FPR never moved.

This is the honest value of the simulation step: it surfaces detector bugs
before a customer's traffic does.

The remaining misses (9 / 800, all labelled block-defiance) were inspected
one by one. Every one is a **failed grind**: deny, then 5–10 evasion variants
(encoding, dot-segment, case, method), every attempt answered 401/403/404,
including the POST attempts — no breakthrough ever happens. By §4.1's
definition that is correctly not a block-defiance alert: the attack did not
succeed. They are left visible rather than papered over by loosening
thresholds. They are not lost, either: exactly this sub-threshold shape is
what the cross-tenant correlator (§11) ships off-site, so a swarm of failed
grinds still surfaces across customers. A local, lower-severity "attempted
defiance" alert is a possible addition, but would need its own FP gate on
the benign + NAT suites before it ships.

## 7. Known limits

- **Spacing beyond the idle window** (default 60s between every attempt) is
  missed unless the window is widened; the hard cap trades some patient-grind
  coverage for a guarantee the detector can't be held open indefinitely.
- **Bodies are rarely in access logs**, so the prompt-leak check needs a
  body-sampling pipeline; the canary-callback check works from URLs alone.
- **Egress needs its own feed** — inbound access logs don't carry
  destinations.
- **Simulation ≠ production.** It proves detector logic and low noise against
  incident-shaped traffic; it does not prove that shape matches a given
  customer's real logs. The next validation step is one real log sample
  through `ingest.py`.

## 8. Deployment and reporting

Ingest runs on nginx/apache combined logs, Cloudflare Logpush JSON, or the
PoC's own JSONL, and emits detections as text or JSONL. In production the flow
is: edge + egress logs → detectors → alert, with an auto-drafted report pack
for ACSC ReportCyber, the customer's cyber insurer, the OAIC (if personal data
is in scope), and the agent operator. Pre-templated, fast reporting is itself a
selling point: in the Medicare case the operator knew in August, told the
government on 10 September, and ASD found out on 15 September.

## 9. Fit

This is the AI-attack-detection module of a compliance-and-monitoring
subscription for Australian conveyancers (ARNECC MPR v8 "secure use of
systems") and GP/allied-health practices (RACGP 6th-edition F8 incident
response), and a white-label feed for MSPs — where the cross-tenant
correlator (§11) is the reason to buy through an MSP rather than per-site.
The methodology and results are also publishable as a research note.

## 10. Hardening round 2 and the honeypot

After the three base detectors, six additions were integrated and each
verified to fire (`unit_checks.py`): cross-session actor-scope state, a
kill-chain correlator, timing classification (`script`/`agent`), evasion-
grammar signatures, Web Bot Auth suppression/upgrade (per session), and a denial-page nonce
tripwire (proof-grade).

Testing the additions surfaced a production-critical false positive. The
cross-session (actor `/24`) scope stitched several distinct humans behind one
office NAT — each hitting a 403 once, then one legitimately logging in — into
a fake block-defiance alert, because it fired on attempt *volume*. The fix: at
actor granularity, volume is meaningless (NAT inflates it), so the slow scope
now requires genuine evasion — multiple distinct variants **and** at least one
hard-evasion grammar class (encoding/dot-segment/case/method/version). Benign
NAT noise (trailing slash, tracking query) never clears it. Regression-gated
in `stress_nat.py`, which also measures actor-scoped cross-session recall
(100% over 200 randomized campaigns).

The honeypot (`honeypot.py`) is a real, deployable stdlib HTTP server that
presents the decoy surface, stamps a one-time nonce into every 403 body, seeds
canary docs, and logs each request as an Event. It deliberately **yields** to
an evasion attempt (a bypass-token or write gets a 200 of inert fake content),
so the full deny→evade→breakthrough chain completes on real traffic — standard
deception practice. `honeypot_drive.py` launches it, fires real HTTP from
benign and agent-style clients over loopback, and runs the detectors on the
server's own log: 54 real requests → 5 correct detections, 0 false positives
on the benign clients. This is the pipeline proven on real HTTP, not simulated
records. Public collection needs deployment on owned infrastructure
(`DEPLOY.md`); real autonomous-agent hits are rare, so the first weeks' value
is a false-positive baseline on real benign traffic — the number a security
buyer asks for.

## 11. Cross-tenant swarm correlation

The distributed-agent case defeats every single-site detector by design: a
swarm splits its work so each target sees one or two quiet probes, and each
site is *right* not to alarm. The campaign is only visible across targets —
which a solo site can't see and a multi-tenant operator (an MSP) can. This is
the part of AgentWall no incumbent sells.

**Signals, not data.** Each tenant runs `extract_signals` over its own events
and emits a signal for every post-deny grind with ≥2 distinct variants —
deliberately *more* sensitive than local alerting, including grinds that never
broke through. A signal carries no customer data: a truncated SHA-256 digest
of (evasion grammar + resource shape), a salted hash of the actor, a
timestamp, the tenant id, and two booleans (hard evasion present,
breakthrough reached). Raw paths, query strings, bodies and real IPs never
leave the tenant. Resource *shape* generalises a path to category + depth
(`/portal/matters` and `/client-area/files` both become `auth|d2`) so firms
with different URLs still correlate on structure.

**Two tiers.** The correlator buckets signals over a sliding window (default
24h) and fires when the same key appears at enough distinct tenants:
- *grammar + shape* (precise): same TTP on the same endpoint type, ≥3 tenants;
- *grammar only* (broad): same TTP on any endpoint type, ≥4 tenants by
  default, the higher bar paying for the broader match.

**Noise control.** Only grammars containing a hard-evasion class are
correlated, the same rule that fixed the NAT false positive (§10); everyone's
stray trailing slash never lines up into a false swarm.

**Results** (`cross_tenant_demo.py`): a swarm spread across 5 tenants, each
below its local threshold — local detectors fire at 0 / 5, the correlator
raises 2 swarm alerts (one per tier). A negative control of unrelated benign
noise with different grammars raises 0. The swarm hidden inside that noise
raises exactly the same 2 alerts, 0 from the noise. This is a constructed
demo, not a measured rate — real multi-tenant data is needed for an FP figure.

**Status.** The correlator is in-process in the PoC. Production needs a
transport — tenants POST signals over mutually authenticated TLS — which is an
open item. The streaming entry point (`ingest`) returns every alert a signal
raises, since one signal can complete both tiers at once; this is
regression-gated in `unit_checks.py` (#7).

---
*PoC code: `events.py`, `simulator.py`, `detectors.py`, `correlation.py`,
`eval.py`, `stress.py`, `stress_nat.py`, `unit_checks.py`,
`cross_tenant_demo.py`, `ingest.py`, `honeypot.py`, `honeypot_drive.py`,
`analyze.py`. Reproduce with `python3 eval.py`, `python3 stress_nat.py`,
`python3 unit_checks.py`, `python3 cross_tenant_demo.py`,
`python3 honeypot_drive.py`.*
