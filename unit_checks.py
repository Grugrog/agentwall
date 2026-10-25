"""Prove each of the six additions actually fires (not dead code), plus
regression gates (#7-#10) for bugs found in review."""
from events import Event
from detectors import run_detectors, BlockDefianceDetector

def mk(sid, ip, rows, **extra):
    ev=[]; t=1000.0
    for r in rows:
        m,p,s = r[0],r[1],r[2]
        kw=dict(session_id=sid,src_ip=ip,user_agent=extra.get('ua','x'),
                method=m,path=p,status=s,truth='attacker')
        if len(r)>3: kw.update(r[3])
        ev.append(Event(ts=t,**kw)); t+=extra.get('gap',0.3)
    return ev

PASS=[]; FAIL=[]
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail and not cond else ""))

print("#3 timing classification (actor_type populated):")
d=run_detectors(mk('t1','5.5.5.1',
    [('GET','/portal',403)]*4+[('PUT','/portal/x',201)], gap=0.05))
bd=[x for x in d if x.detector=='block_defiance']
check("fast ms grind -> actor_type=script", bd and bd[0].actor_type=='script',
      f"got {bd[0].actor_type if bd else None}")
d=run_detectors(mk('t2','5.5.5.2',
    [('GET','/portal',403)]*4+[('PUT','/portal/x',201)], gap=5.0))
bd=[x for x in d if x.detector=='block_defiance']
check("seconds grind -> actor_type=agent", bd and bd[0].actor_type=='agent',
      f"got {bd[0].actor_type if bd else None}")

print("#4 evasion-grammar signature populated:")
rows=[('GET','/portal',403),('GET','/portal/',403),('GET','/portal%2e',403),
      ('POST','/portal',200)]
d=run_detectors(mk('g1','5.5.6.1',rows))
bd=[x for x in d if x.detector=='block_defiance']
check("signature non-empty", bd and bd[0].signature!="",
      f"got '{bd[0].signature if bd else None}'")

print("#5 Web Bot Auth suppression + unverified upgrade:")
# verified agent doing the same grind -> suppressed
rows=[('GET','/portal',403,{'web_bot_auth':True,'user_agent':'ChatGPT-User/1.0'})]+\
     [('GET','/portal/',403,{'web_bot_auth':True})]*3+\
     [('POST','/portal',200,{'web_bot_auth':True})]
d=run_detectors(mk('w1','5.5.7.1',rows))
check("verified WBA agent suppressed", not [x for x in d if x.detector=='block_defiance'])
# claims agent (bot UA) but NO WBA -> critical
rows=[('GET','/portal',403),('GET','/portal/',403),('GET','/portal%2e',403),
      ('POST','/portal',200)]
d=run_detectors(mk('w2','5.5.7.2',rows,ua='python-requests/2.32'))
bd=[x for x in d if x.detector=='block_defiance']
check("unverified agent UA -> critical", bd and bd[0].severity=='critical',
      f"got {bd[0].severity if bd else None}")

print("#6 denial-page tripwire proof-grade:")
rows=[('GET','/portal',403,{'denial_nonce':'NONCE123'}),
      ('GET','/cb/NONCE123',200)]
d=run_detectors(mk('n1','5.5.8.1',rows))
inj=[x for x in d if x.detector=='injection_tripwire']
check("denial-nonce callback -> proof", inj and getattr(inj[0],'confidence','')=='proof',
      f"got conf='{getattr(inj[0],'confidence','') if inj else None}'")

print("#2 kill-chain multi-stage:")
# a GET->POST switch on the SAME path is a login form, not evasion, so the
# chain needs a real hard-evasion variant (%2e) before the breakthrough
rows=[('GET','/nope',404),('GET','/portal',403),('GET','/portal%2e',403),
      ('GET','/PORTAL',200),('PUT','/portal/x',201)]
d=run_detectors(mk('k1','5.5.9.1',rows))
kc=[x for x in d if x.detector=='kill_chain']
check("kill_chain fires on multi-stage", bool(kc),
      kc[0].reason if kc else "no fire")

print("#1 cross-session (slow scope) — patient grind across DIFFERENT sessions:")
# same actor /24, different session ids, spaced 120s (beyond fast 60s window)
ev=[]; t=1000.0
seq=[('sessA','/portal',403),('sessB','/portal/',403),('sessC','/portal%2e',403),
     ('sessD','/portal?x=1',403),('sessE','/portal',200)]
for sid,p,s in seq:
    ev.append(Event(ts=t,session_id=sid,src_ip='5.5.10.7',user_agent='python-requests/2.32',
                    method='GET',path=p,status=s,truth='attacker')); t+=120.0
d=run_detectors(ev)
bd=[x for x in d if x.detector=='block_defiance']
check("cross-session grind caught by slow scope", bool(bd),
      bd[0].reason if bd else "MISSED")

print("#7 correlator streaming ingest surfaces BOTH tiers:")
# one signal completing grammar+shape and grammar-only at once must yield 2 alerts
from correlation import CrossTenantCorrelator, TenantSignal, _digest
c=CrossTenantCorrelator(min_tenants=2, min_tenants_grammar=2)
dg=_digest("encoding,dotseg","auth|d1")
sig=lambda t,ts: TenantSignal(tenant_id=t,ts=ts,digest=dg,signature="encoding,dotseg",
    shape="auth|d1",actor_hash=t,hard=True,reached_breakthrough=False)
c.ingest(sig('A',0)); al=c.ingest(sig('B',1))
check("single signal -> both tier alerts", sorted(a.scope for a in al)==['grammar','grammar+shape'],
      f"got {[a.scope for a in al]}")

print("#8 denial-page PROOF not swallowed by an earlier canary hit (same session):")
d=run_detectors(mk('p1','5.5.11.1',[('GET','/cb/aaa',200),
    ('GET','/portal',403,{'denial_nonce':'nnn'}),('GET','/cb/nnn',200)]))
check("canary then proof -> both fire", sum(1 for x in d if x.detector=='injection_tripwire')==2
      and any(x.confidence=='proof' for x in d), f"got {[x.reason[:40] for x in d]}")

print("#9 Web Bot Auth is per session: a verified neighbour in the /24 can't hide an attacker:")
ev=mk('bot','20.1.1.5',[('GET','/',200,{'web_bot_auth':True})])
ev+=[Event(ts=1010+i,session_id='atk',src_ip='20.1.1.99',user_agent='python-requests/2.32',
           method=m,path=p,status=s,truth='attacker') for i,(m,p,s) in enumerate(
     [('GET','/portal',403),('GET','/portal/',403),('GET','/portal%2e',403),('GET','/PORTAL',200)])]
check("attacker next to verified agent still caught",
      any(x.detector=='block_defiance' for x in run_detectors(ev)))

print("#10 normaliser collapses ; / %20 / double-encoding variants:")
from detectors import _resource_key
ks={_resource_key(p) for p in ['/portal','/portal;','/portal..;/','/;/portal','/portal%20','/portal%252f']}
check("all variants -> one key", ks=={'portal'}, f"got {ks}")

print("#11 honeypot logs stdlib-rejected requests (414 used to crash the handler):")
import json, os, socket, tempfile
from honeypot import Honeypot
_log = os.path.join(tempfile.mkdtemp(), "hp.jsonl")
hp = Honeypot(host="127.0.0.1", port=0, log_path=_log); hp.start_background()
def _raw(data):
    s = socket.create_connection(("127.0.0.1", hp.port), timeout=3)
    s.sendall(data); s.shutdown(socket.SHUT_WR)
    while s.recv(4096): pass
    s.close()
_raw(b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n")                  # fresh conn
_raw(b"GET /about HTTP/1.1\r\nUser-Agent: PRIOR-UA\r\n\r\n"
     b"GET /" + b"b" * 70000 + b" HTTP/1.1\r\n\r\n")                   # keep-alive
_raw(b"HEAD /nope HTTP/1.1\r\n\r\n")
hp.stop()
recs = [json.loads(l) for l in open(_log)]
r414 = [r for r in recs if r["status"] == 414]
check("414 on fresh + keep-alive conn both logged", len(r414) == 2, f"got {len(r414)}")
check("keep-alive 414 doesn't inherit prior UA",
      all(r["user_agent"] == "" for r in r414) and all(r["path"].startswith("GET /") for r in r414))
check("HEAD logs 0 bytes sent", [r["bytes_out"] for r in recs if r["method"] == "HEAD"] == [0])

print(f"\n{len(PASS)} pass, {len(FAIL)} fail")
if FAIL: print("FAILED:", FAIL)
