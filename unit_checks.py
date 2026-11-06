"""
Prove each of the six hardening additions actually fires (not dead code).

  #1 cross-session (slow actor-scope) state
  #2 kill-chain correlator
  #3 timing classification (script / agent)
  #4 evasion-grammar signature
  #5 Web Bot Auth suppression (verified) + upgrade (unverified agent UA)
  #6 denial-page nonce tripwire (proof-grade)

Each check runs the real detectors over a tiny hand-built event stream and
asserts the expected detection/field. Run: python3 unit_checks.py
"""
from events import Event
from detectors import run_detectors


def mk(sid, ip, rows, ua="x", gap=0.3):
    """rows: list of (method, path, status[, extra_kwargs_dict])."""
    ev = []
    t = 1000.0
    for r in rows:
        kw = dict(session_id=sid, src_ip=ip, user_agent=ua,
                  method=r[0], path=r[1], status=r[2], truth="attacker")
        if len(r) > 3:
            kw.update(r[3])
        ev.append(Event(ts=t, **kw))
        t += gap
    return ev


PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    tag = "PASS" if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f"  -> {detail}" if detail and not cond else ""))


print("#3 timing classification (actor_type populated):")
d = run_detectors(mk("t1", "5.5.5.1",
    [("GET", "/portal", 403)] * 4 + [("PUT", "/portal/x", 201)], gap=0.05))
bd = [x for x in d if x.detector == "block_defiance"]
check("fast ms grind -> actor_type=script", bool(bd) and bd[0].actor_type == "script",
      f"got {bd[0].actor_type if bd else None}")
d = run_detectors(mk("t2", "5.5.5.2",
    [("GET", "/portal", 403)] * 4 + [("PUT", "/portal/x", 201)], gap=5.0))
bd = [x for x in d if x.detector == "block_defiance"]
check("seconds grind -> actor_type=agent", bool(bd) and bd[0].actor_type == "agent",
      f"got {bd[0].actor_type if bd else None}")

print("#4 evasion-grammar signature populated:")
d = run_detectors(mk("g1", "5.5.6.1",
    [("GET", "/portal", 403), ("GET", "/portal/", 403),
     ("GET", "/portal%2e", 403), ("POST", "/portal", 200)]))
bd = [x for x in d if x.detector == "block_defiance"]
check("signature non-empty", bool(bd) and bd[0].signature != "",
      f"got '{bd[0].signature if bd else None}'")

print("#5 Web Bot Auth suppression + unverified upgrade:")
rows = ([("GET", "/portal", 403, {"web_bot_auth": True, "user_agent": "ChatGPT-User/1.0"})]
        + [("GET", "/portal/", 403, {"web_bot_auth": True})] * 3
        + [("POST", "/portal", 200, {"web_bot_auth": True})])
d = run_detectors(mk("w1", "5.5.7.1", rows))
check("verified WBA agent suppressed",
      not [x for x in d if x.detector == "block_defiance"])
d = run_detectors(mk("w2", "5.5.7.2",
    [("GET", "/portal", 403), ("GET", "/portal/", 403),
     ("GET", "/portal%2e", 403), ("POST", "/portal", 200)],
    ua="python-requests/2.32"))
bd = [x for x in d if x.detector == "block_defiance"]
check("unverified agent UA -> critical", bool(bd) and bd[0].severity == "critical",
      f"got {bd[0].severity if bd else None}")

print("#6 denial-page tripwire proof-grade:")
d = run_detectors(mk("n1", "5.5.8.1",
    [("GET", "/portal", 403, {"denial_nonce": "NONCE123"}),
     ("GET", "/cb/NONCE123", 200)]))
inj = [x for x in d if x.detector == "injection_tripwire"]
check("denial-nonce callback -> proof",
      bool(inj) and getattr(inj[0], "confidence", "") == "proof",
      f"got conf='{getattr(inj[0], 'confidence', '') if inj else None}'")

print("#2 kill-chain multi-stage:")
d = run_detectors(mk("k1", "5.5.9.1",
    [("GET", "/nope", 404), ("GET", "/portal", 403), ("GET", "/portal/", 403),
     ("POST", "/portal", 200), ("PUT", "/portal/x", 201)]))
check("kill_chain fires on multi-stage",
      bool([x for x in d if x.detector == "kill_chain"]))

print("#1 cross-session (slow scope) -- patient grind across DIFFERENT sessions:")
ev = []
t = 1000.0
for sid, p, s in [("sessA", "/portal", 403), ("sessB", "/portal/", 403),
                  ("sessC", "/portal%2e", 403), ("sessD", "/portal?x=1", 403),
                  ("sessE", "/portal", 200)]:
    ev.append(Event(ts=t, session_id=sid, src_ip="5.5.10.7",
                    user_agent="python-requests/2.32", method="GET",
                    path=p, status=s, truth="attacker"))
    t += 120.0
check("cross-session grind caught by slow scope",
      bool([x for x in run_detectors(ev) if x.detector == "block_defiance"]))

print(f"\n{len(PASS)} pass, {len(FAIL)} fail")
if FAIL:
    print("FAILED:", FAIL)
    raise SystemExit(1)
