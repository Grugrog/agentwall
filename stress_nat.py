"""
The /24 clustering false-positive risk (the one the research flagged).

Scenario: a corporate office / CGNAT where MANY distinct humans share one /24.
Several independently fumble onto a 403 (expired session, wrong bookmark),
and — crucially — one of them then LEGITIMATELY logs in and gets a 200 on the
same resource. The slow (actor-cluster) scope groups them all under net:x/24.
If it treats the accumulated denials + the legit 200 as a block-defiance
breakthrough, that's a false positive that would sink the product.

Also tests CGNAT with a genuine attacker hidden in the same /24, to confirm
we don't lose the real one while suppressing the noise.
"""
from events import Event
from detectors import run_detectors

def run_case(name, events, expect_fire):
    d=[x for x in run_detectors(events) if x.detector in ('block_defiance','kill_chain')]
    fired=bool(d)
    ok = fired==expect_fire
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: "
          f"{'fired' if fired else 'quiet'} (expected {'fire' if expect_fire else 'quiet'})")
    if d and not expect_fire:
        print("       -> FALSE POSITIVE:", d[0].reason[:120])
    return ok

NET="203.0.113."  # one /24
results=[]

# Case 1: 6 different humans behind one /24, each hits /portal 403 once over
# 10 minutes, then human #7 (same /24) legitimately logs in -> 200. Distinct
# browser UAs, human spacing. MUST NOT fire.
ev=[]; t=1000.0
for i in range(6):
    ev.append(Event(ts=t,session_id=f"h{i}",src_ip=f"{NET}{10+i}",
        user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/141.0",
        method="GET",path="/portal",status=403,has_referer=True,truth="human"))
    t+=90.0
ev.append(Event(ts=t,session_id="h7",src_ip=f"{NET}17",
    user_agent="Mozilla/5.0 (Macintosh) Safari/605.1",
    method="GET",path="/portal",status=200,has_referer=True,truth="human"))
results.append(run_case("6 humans 403 + 1 legit login, shared /24", ev, expect_fire=False))

# Case 2: same but the legit user does a POST (form submit) after login. Still benign.
ev=[]; t=1000.0
for i in range(5):
    ev.append(Event(ts=t,session_id=f"h{i}",src_ip=f"{NET}{20+i}",
        user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/141.0",
        method="GET",path="/portal/matters",status=403,has_referer=True,truth="human"))
    t+=120.0
ev.append(Event(ts=t,session_id="hx",src_ip=f"{NET}25",
    user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/141.0",
    method="POST",path="/portal/matters",status=200,has_referer=True,truth="human"))
results.append(run_case("5 humans 403 + 1 legit POST, shared /24", ev, expect_fire=False))

# Case 3: a REAL attacker in the same busy /24 — must still be caught.
# benign noise from neighbours + one actor doing the evasion grammar itself.
ev=[]; t=1000.0
for i in range(4):  # neighbour noise
    ev.append(Event(ts=t,session_id=f"n{i}",src_ip=f"{NET}{40+i}",
        user_agent="Mozilla/5.0 Chrome/141.0",method="GET",path="/portal",
        status=403,has_referer=True,truth="human")); t+=50.0
# the attacker: one IP, evasion variants, breakthrough + write
for p,s,m in [("/portal",403,"GET"),("/portal/",403,"GET"),("/portal%2e",403,"GET"),
              ("/PORTAL",200,"GET"),("/portal/x_ab",201,"PUT")]:
    ev.append(Event(ts=t,session_id="atk",src_ip=f"{NET}99",
        user_agent="python-requests/2.32",method=m,path=p,status=s,
        has_referer=False,truth="attacker")); t+=0.3
results.append(run_case("real attacker inside busy /24 still caught", ev, expect_fire=True))

# Cases 4-6: everyday benign flows that kill_chain once mistook for a
# deny -> breakthrough "jump". None involves an evasion variant.
H="Mozilla/5.0 (Windows NT 10.0) Chrome/141.0"
def _h(t,sid,ip,m,p,s): return Event(ts=t,session_id=sid,src_ip=ip,user_agent=H,
    method=m,path=p,status=s,has_referer=True,truth="human")
results.append(run_case("403 -> login -> 200 on a portal sub-page", [
    _h(0,"l1",f"{NET}60","GET","/portal",403), _h(5,"l1",f"{NET}60","POST","/login",200),
    _h(8,"l1",f"{NET}60","GET","/portal/home",200)], expect_fire=False))
results.append(run_case("denied on a child, clicks back to the parent", [
    _h(0,"l2",f"{NET}61","GET","/portal/admin",403),
    _h(4,"l2",f"{NET}61","GET","/portal",200)], expect_fire=False))
results.append(run_case("NAT: one user 403s, a colleague uses the portal", [
    _h(0,"l3",f"{NET}62","GET","/portal",403),
    _h(60,"l4",f"{NET}63","GET","/portal/matters",200)], expect_fire=False))

print(f"\n{sum(results)}/{len(results)} passed")

# ---------------------------------------------------------------------------
# Cross-session recall, scored by ACTOR (the correct unit for the slow scope).
# Many randomized cross-session grinds: one /24 each, attempts split across
# 3-6 distinct session ids, spaced beyond the fast 60s window, using real
# evasion encodings. The slow scope must catch each as ONE actor campaign.
# ---------------------------------------------------------------------------
import random
from detectors import run_detectors as _rd

_ENC = ["/portal", "/portal/", "/portal%2e", "/./portal", "/../portal",
        "/PORTAL", "/portal?x=1", "/portal/."]
def _crosssession_case(rng):
    net = f"{rng.randint(11,250)}.{rng.randint(0,255)}.{rng.randint(0,255)}."
    ip = f"{net}{rng.randint(2,250)}"
    t = 1000.0 + rng.uniform(0, 5)
    ev = []
    variants = rng.sample(_ENC, k=rng.randint(4, 6))
    for i, p in enumerate(variants):
        sid = f"s{rng.randint(0,10**9)}"          # fresh session each time
        last = (i == len(variants) - 1)
        status, method = (200, "GET") if last else (403, "GET")
        ev.append(Event(ts=t, session_id=sid, src_ip=ip,
                        user_agent="python-requests/2.32", method=method,
                        path=p, status=status, has_referer=False,
                        truth="attacker"))
        t += rng.uniform(70, 170)                  # beyond fast window
    # write-back from yet another session
    ev.append(Event(ts=t, session_id=f"s{rng.randint(0,10**9)}", src_ip=ip,
                    user_agent="python-requests/2.32", method="PUT",
                    path="/portal/x_" + str(rng.randint(0,10**6)), status=201,
                    has_referer=False, truth="attacker"))
    return ev, ip

caught = 0; N = 200
rng = random.Random(7)
for _ in range(N):
    ev, ip = _crosssession_case(rng)
    d = [x for x in _rd(ev) if x.detector in ("block_defiance", "kill_chain")]
    if d:
        caught += 1
print(f"\nCross-session recall (actor-scoped, {N} campaigns): "
      f"{caught}/{N} = {100*caught/N:.1f}%")

