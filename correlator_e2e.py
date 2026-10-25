#!/usr/bin/env python3
"""
End-to-end gate for the correlator transport: a real HTTPS server on
loopback (throwaway self-signed cert), tenants pushing signals over TLS with
HMAC auth. Proves the swarm is still caught over the wire, benign noise still
isn't, and every way a tenant could lie or leak is refused.
"""
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict

from events import Event
from correlation import CrossTenantCorrelator, TenantSignal, _digest, extract_signals
from correlator_service import CorrelatorService, push, sign

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + ("" if ok else f" -- {detail}"))


def make_cert(d):
    crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    return crt, key


def grind(net, resource, variants, t0):
    ip, t, ev = net + ".9", t0, []
    for p in [resource] + variants:
        ev.append(Event(ts=t, session_id="s", src_ip=ip, user_agent="python-requests/2.32",
                        method="GET", path=p, status=403, truth="attacker")); t += 30
    return ev


def raw_post(url, cafile, tenant, secret, body, ts=None, nonce="n" * 16, sig=None):
    ts = str(int(time.time()) if ts is None else ts)
    req = urllib.request.Request(url + "/v1/signals", data=body, method="POST", headers={
        "X-AW-Tenant": tenant, "X-AW-Timestamp": ts, "X-AW-Nonce": nonce,
        "X-AW-Signature": sig or sign(secret, tenant, ts, nonce, body)})
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(cafile=cafile)) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    if not shutil.which("openssl"):
        print("openssl not found; cannot mint a test cert"); return 1
    tmp = tempfile.mkdtemp()
    crt, key = make_cert(tmp)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(crt, key)

    swarm = {
        "conveyancer-A": ("203.0.11", "/portal", ["/portal%2e", "/../portal"]),
        "conveyancer-B": ("198.51.1", "/client-area", ["/client-area%2e", "/../client-area"]),
        "gp-clinic-C":   ("192.0.2",  "/portal", ["/portal%2e", "/../portal"]),
        "law-firm-D":    ("203.0.12", "/admin", ["/admin%2e", "/../admin"]),
        "conveyancer-E": ("198.51.2", "/portal", ["/portal%2e", "/../portal"]),
    }
    noise = {
        "shop-F": ("203.0.20", "/cart", ["/cart/"]),
        "blog-G": ("198.51.3", "/post", ["/post?utm=x"]),
        "news-H": ("192.0.9", "/feed", ["/feed/"]),
    }
    keys = {t: os.urandom(32) for t in list(swarm) + list(noise)}
    alerts = []
    svc = CorrelatorService(keys, "127.0.0.1", 0, ctx,
                            CrossTenantCorrelator(min_tenants=3),
                            alerts_path=os.path.join(tmp, "alerts.jsonl"),
                            on_alert=alerts.append).start_background()
    url = f"https://localhost:{svc.port}"
    now = time.time() - 6 * 3600          # signals spread over the last few hours

    print("=== swarm + noise pushed over TLS ===")
    for i, (t, (net, res, var)) in enumerate(noise.items()):
        sigs = extract_signals(grind(net, res, var, now + i * 600), t)
        push(url, t, keys[t], sigs, cafile=crt)
    check("benign noise alone -> no swarm alert", not alerts, f"{[a.reason for a in alerts]}")
    total = 0
    for i, (t, (net, res, var)) in enumerate(swarm.items()):
        sigs = extract_signals(grind(net, res, var, now + i * 3600), t)
        total += push(url, t, keys[t], sigs, cafile=crt)
    check("all swarm signals accepted", total == len(swarm), f"accepted {total}")
    check("swarm caught over the wire, both tiers",
          sorted(a.scope for a in alerts) == ["grammar", "grammar+shape"],
          f"{[a.scope for a in alerts]}")
    with open(os.path.join(tmp, "alerts.jsonl")) as f:
        recs = [json.loads(l) for l in f]
    check("alerts written to JSONL", len(recs) == len(alerts) and all("reason" in r for r in recs))

    print("=== rejections ===")
    t, sec = "conveyancer-A", keys["conveyancer-A"]
    dg = _digest("encoding,dotseg", "auth|d1")
    good = asdict(TenantSignal(tenant_id=t, ts=time.time(), digest=dg,
                               signature="encoding,dotseg", shape="auth|d1",
                               actor_hash="0" * 12, hard=True, reached_breakthrough=False))
    body = lambda *s: json.dumps({"signals": list(s)}).encode()
    before = len(alerts)

    check("valid signed batch -> 200", raw_post(url, crt, t, sec, body(good), nonce="a" * 16) == 200)
    check("replayed nonce -> 401", raw_post(url, crt, t, sec, body(good), nonce="a" * 16) == 401)
    check("wrong secret -> 401", raw_post(url, crt, t, os.urandom(32), body(good), nonce="b" * 16) == 401)
    check("unknown tenant -> 401", raw_post(url, crt, "nobody", sec, body(good), nonce="c" * 16) == 401)
    check("body tampered after signing -> 401",
          raw_post(url, crt, t, sec, body(good), nonce="d" * 16,
                   sig=sign(sec, t, str(int(time.time())), "d" * 16, body())) == 401)
    check("stale timestamp -> 401",
          raw_post(url, crt, t, sec, body(good), ts=int(time.time()) - 3600, nonce="e" * 16) == 401)
    # one key forging a swarm of made-up tenants
    forged = [dict(good, tenant_id=f"fake-{i}") for i in range(5)]
    check("signal for another tenant_id -> 403",
          raw_post(url, crt, t, sec, body(*forged), nonce="f" * 16) == 403)
    check("digest not matching signature/shape -> 400",
          raw_post(url, crt, t, sec, body(dict(good, digest="f" * 16)), nonce="g" * 16) == 400)
    check("claiming hard on a soft grammar -> 400",
          raw_post(url, crt, t, sec, body(dict(good, signature="trailing",
                   digest=_digest("trailing", "auth|d1"))), nonce="h" * 16) == 400)
    check("extra field (raw path) refused, not dropped -> 400",
          raw_post(url, crt, t, sec, body(dict(good, path="/portal/matters/123")), nonce="i" * 16) == 400)
    check("future timestamp on a signal -> 400",
          raw_post(url, crt, t, sec, body(dict(good, ts=time.time() + 86400)), nonce="j" * 16) == 400)
    check("batch is all-or-nothing (good + bad -> 400)",
          raw_post(url, crt, t, sec, body(good, dict(good, hard="yes")), nonce="k" * 16) == 400)
    check("no alerts from any rejected or single-tenant traffic", len(alerts) == before)
    try:
        push(f"http://203.0.113.5:{svc.port}", t, sec, [TenantSignal(**good)])
        check("client refuses plain HTTP off loopback", False, "sent")
    except ValueError:
        check("client refuses plain HTTP off loopback", True)
    try:
        urllib.request.urlopen(url + "/v1/signals", data=b"{}",
                               context=ssl.create_default_context(), timeout=5)
        check("untrusted cert refused by default client", False, "connected")
    except urllib.error.URLError as e:
        check("untrusted cert refused by default client",
              isinstance(e.reason, ssl.SSLCertVerificationError), repr(e.reason))

    svc.stop()
    shutil.rmtree(tmp)
    print(f"\n{len(PASS)} pass, {len(FAIL)} fail")
    if FAIL:
        print("FAILED:", FAIL)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
