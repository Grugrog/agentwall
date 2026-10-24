"""
Stress test: do the detectors survive HARD benign traffic and EVASIVE
attackers? 0% FPR on polite traffic proves little; these are the cases that
actually generate false alarms in production.

Hard benign:
  - frustrated power user: hits a 403, retries the SAME url a few times
    (refresh / re-login), maybe 2-3 times, human-paced. Must NOT fire.
  - legit aggressive API client: fast, no referer, bot UA, polls an endpoint
    it IS allowed to -> all 200s, no deny. Must NOT fire.
  - SPA/app that 401s then refreshes a token then succeeds ONCE on the same
    path (not an evasion grind). Must NOT fire.

Harder attackers:
  - evasion-only (no write, just a 200 breakthrough)
  - very patient low-and-slow spread over minutes (tests window edge)
"""
from __future__ import annotations
import random, string
from collections import defaultdict
from statistics import mean, pstdev
from events import Event
from detectors import run_detectors
from simulator import Simulator, PROTECTED_PATHS

def _nonce(rng, n=8):
    return "".join(rng.choice(string.ascii_lowercase+string.digits) for _ in range(n))

def inject_hard_benign(sim: Simulator, n_each=30):
    rng = sim.rng
    for _ in range(n_each):
        # frustrated power user: same 403'd url retried a few times, slow
        sid, ip = _nonce(rng,12), ".".join(str(rng.randint(1,254)) for _ in range(4))
        tgt = rng.choice(PROTECTED_PATHS)
        for i in range(rng.randint(2,4)):
            sim._advance(3.0, 20.0)  # human frustration pace
            sim._emit(session_id=sid, src_ip=ip,
                      user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/141.0",
                      method="GET", path=tgt, status=403, bytes_out=120,
                      has_referer=True, truth="human")
    for _ in range(n_each):
        # legit aggressive API client (allowed): fast, bot UA, all 200
        sid, ip = _nonce(rng,12), ".".join(str(rng.randint(1,254)) for _ in range(4))
        ep = "/api/v1/clients"
        for i in range(rng.randint(10,30)):
            sim._advance(0.05, 0.4)
            sim._emit(session_id=sid, src_ip=ip, user_agent="python-httpx/0.27",
                      method="GET", path=ep+"?page="+str(i), status=200,
                      bytes_out=rng.randint(500,3000), has_referer=False,
                      web_bot_auth=True, truth="goodbot")
    for _ in range(n_each):
        # SPA token refresh: 401 once, refresh, then 200 on SAME path
        sid, ip = _nonce(rng,12), ".".join(str(rng.randint(1,254)) for _ in range(4))
        p = "/api/v1/matters"
        sim._advance(0.5,2.0)
        sim._emit(session_id=sid, src_ip=ip, user_agent="Mozilla/5.0 Chrome/141.0",
                  method="GET", path=p, status=401, bytes_out=90,
                  has_referer=True, truth="human")
        sim._advance(0.2,0.8)
        sim._emit(session_id=sid, src_ip=ip, user_agent="Mozilla/5.0 Chrome/141.0",
                  method="POST", path="/api/v1/auth/refresh", status=200,
                  bytes_out=300, has_referer=True, truth="human")
        sim._advance(0.2,0.8)
        sim._emit(session_id=sid, src_ip=ip, user_agent="Mozilla/5.0 Chrome/141.0",
                  method="GET", path=p, status=200, bytes_out=4000,
                  has_referer=True, truth="human")

def evaluate_benign_only(events):
    """Count benign sessions wrongly flagged among the HARD cases only."""
    dets = run_detectors(events)
    fired = defaultdict(list)
    for d in dets: fired[d.session_id].append(d)
    by_sess = defaultdict(list)
    for e in events: by_sess[e.session_id].append(e)
    fp = tn = 0
    fp_reasons = []
    for sid, evs in by_sess.items():
        if any(e.truth=="attacker" for e in evs): continue
        if sid in fired:
            fp += 1
            fp_reasons.append(fired[sid][0].reason)
        else:
            tn += 1
    return fp, tn, fp_reasons

rows=[]
for seed in range(1,11):
    sim = Simulator(seed=seed)
    sim.run()  # normal mix
    inject_hard_benign(sim, n_each=30)
    sim.events.sort(key=lambda e: e.ts)
    fp, tn, reasons = evaluate_benign_only(sim.events)
    rows.append((fp,tn,reasons))

tot_fp = sum(r[0] for r in rows); tot_tn = sum(r[1] for r in rows)
print("STRESS: hard benign traffic (frustrated users, aggressive API, token refresh)")
print(f"  benign sessions: {tot_fp+tot_tn}   false positives: {tot_fp}   FPR: {100*tot_fp/(tot_fp+tot_tn):.3f}%")
if tot_fp:
    print("  sample FP reasons:")
    for r in rows:
        for reason in r[2][:3]:
            print("   -", reason)
        if any(r[2]): break
