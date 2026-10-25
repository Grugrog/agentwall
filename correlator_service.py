#!/usr/bin/env python3
"""
Correlator transport: tenants POST privacy-preserving signals to a central
CrossTenantCorrelator over TLS, authenticated per tenant. Stdlib only.

    # operator
    python3 correlator_service.py serve --keys tenant_keys.json \
        --cert cert.pem --key key.pem --alerts swarm_alerts.jsonl
    # tenant (runs extract_signals on its own logs, ships only the digests)
    python3 correlator_service.py push --url https://corr.example:8443 \
        --tenant conveyancer-A --secret-file a.secret access.log

Wire format: POST /v1/signals, body {"signals": [TenantSignal-as-dict, ...]}.
Auth headers:
    X-AW-Tenant     tenant id (must match an entry in the keys file)
    X-AW-Timestamp  unix seconds; rejected if more than MAX_SKEW_S off
    X-AW-Nonce      random, single use within the skew window (no replay)
    X-AW-Signature  hex HMAC-SHA256(secret, tenant\\ntimestamp\\nnonce\\n + body)

The server trusts nothing a tenant sends:
  * every signal's tenant_id must equal the authenticated tenant, so one key
    can't fabricate a "swarm" out of several made-up tenants;
  * digest and hard are recomputed from (signature, shape) and must match, so
    a tenant can't claim hard evasion or collide someone else's bucket;
  * the field set is exact -- an extra field (a raw path, an IP) is refused
    rather than dropped, so a misconfigured tenant can't leak customer data
    into the correlator even by accident;
  * a batch is all-or-nothing.
The response is only {"accepted": n}: whether other tenants share a digest is
never reflected back, so a tenant can't probe the hive.

Detect-and-report only: swarm alerts go to a JSONL file for the operator.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional

from detectors import HARD_EVASION
from correlation import (CrossTenantCorrelator, SwarmAlert, TenantSignal,
                         _digest, extract_signals)

MAX_SKEW_S = 300
MAX_BODY = 256 * 1024
MAX_SIGNALS = 1000

_FIELDS = {f.name for f in fields(TenantSignal)}
_GRAMMAR = {"encoding", "dotseg", "case", "method", "version", "trailing", "route"}
_RE_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RE_SHAPE = re.compile(r"^[a-z]{1,16}\|d\d{1,3}$")
_RE_HEX = lambda n: re.compile(r"^[0-9a-f]{%d}$" % n)
_RE_DIGEST, _RE_ACTOR = _RE_HEX(16), _RE_HEX(12)


def sign(secret: bytes, tenant: str, ts: str, nonce: str, body: bytes) -> str:
    msg = f"{tenant}\n{ts}\n{nonce}\n".encode() + body
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


class Rejected(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code = code


def validate_signal(d: object, tenant: str, now: float,
                    max_age_s: Optional[float]) -> TenantSignal:
    if not isinstance(d, dict) or set(d) != _FIELDS:
        raise Rejected(400, f"signal fields must be exactly {sorted(_FIELDS)}")
    if d["tenant_id"] != tenant:
        raise Rejected(403, "signal tenant_id does not match authenticated tenant")
    ts = d["ts"]
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
        raise Rejected(400, "ts must be a finite number")
    if ts > now + MAX_SKEW_S:
        raise Rejected(400, "ts is in the future")
    if max_age_s is not None and ts < now - max_age_s:
        raise Rejected(400, "ts is older than the correlation window")
    sig, shape = d["signature"], d["shape"]
    if not isinstance(sig, str) or len(sig) > 512 or not sig \
            or any(p not in _GRAMMAR for p in sig.split(",")):
        raise Rejected(400, "signature must be a comma list of grammar classes")
    if not isinstance(shape, str) or not _RE_SHAPE.match(shape):
        raise Rejected(400, "bad shape")
    if not isinstance(d["digest"], str) or not _RE_DIGEST.match(d["digest"]) \
            or d["digest"] != _digest(sig, shape):
        raise Rejected(400, "digest does not match signature/shape")
    if not isinstance(d["actor_hash"], str) or not _RE_ACTOR.match(d["actor_hash"]):
        raise Rejected(400, "bad actor_hash")
    if d["hard"] is not bool(set(sig.split(",")) & HARD_EVASION):
        raise Rejected(400, "hard does not match signature")
    if not isinstance(d["reached_breakthrough"], bool):
        raise Rejected(400, "reached_breakthrough must be a bool")
    return TenantSignal(**d)


class CorrelatorService:
    """HTTP(S) front for one CrossTenantCorrelator. Ingest is serialised under
    a lock; the correlator itself is not thread-safe."""

    def __init__(self, keys: Dict[str, bytes], host="127.0.0.1", port=8443,
                 ssl_context: Optional[ssl.SSLContext] = None,
                 correlator: Optional[CrossTenantCorrelator] = None,
                 alerts_path: Optional[str] = None,
                 on_alert: Optional[Callable[[SwarmAlert], None]] = None,
                 max_age_s: Optional[float] = None,
                 clock: Callable[[], float] = time.time):
        for t in keys:
            if not _RE_TENANT.match(t):
                raise ValueError(f"bad tenant id in keys: {t!r}")
        self.keys = keys
        self.corr = correlator or CrossTenantCorrelator()
        # None -> the correlation window; 0 -> no age limit (replaying history)
        self.max_age_s = (self.corr.window_s if max_age_s is None
                          else max_age_s) or None
        self.on_alert = on_alert
        self.clock = clock
        self._lock = threading.Lock()
        self._nonces: Dict[str, float] = {}
        # opened now so an unwritable path fails at startup, not per alert
        self._alerts_f = open(alerts_path, "a") if alerts_path else None
        svc = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 15                    # a stalled client can't pin a thread
            server_version = "agentwall-correlator"
            sys_version = ""

            def log_message(self, *a):
                pass

            def _reply(self, code: int, obj: dict):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if code >= 400:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._reply(404, {"error": "not found"})

            def do_POST(self):
                try:
                    if self.path != "/v1/signals":
                        raise Rejected(404, "not found")
                    try:
                        n = int(self.headers.get("Content-Length", ""))
                    except ValueError:
                        raise Rejected(411, "Content-Length required")
                    if n < 0 or n > MAX_BODY:
                        raise Rejected(413, "body too large")
                    body = self.rfile.read(n)
                    if len(body) != n:
                        raise Rejected(400, "truncated body")
                    accepted = svc.handle(self.headers, body)
                    self._reply(200, {"accepted": accepted})
                except Rejected as r:
                    self._reply(r.code, {"error": str(r)})

        self.httpd = _Server((host, port), Handler)
        self.httpd.ssl_context = ssl_context
        self.port = self.httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    # -- request handling -------------------------------------------------
    def _authenticate(self, headers, body: bytes) -> str:
        tenant = headers.get("X-AW-Tenant", "")
        ts = headers.get("X-AW-Timestamp", "")
        nonce = headers.get("X-AW-Nonce", "")
        got = headers.get("X-AW-Signature", "")
        secret = self.keys.get(tenant)
        # same 401 for unknown tenant and bad signature: don't confirm ids
        if secret is None or not (8 <= len(nonce) <= 64) or not ts.isdigit():
            raise Rejected(401, "unauthorised")
        if not hmac.compare_digest(sign(secret, tenant, ts, nonce, body), got):
            raise Rejected(401, "unauthorised")
        now = self.clock()
        if abs(now - int(ts)) > MAX_SKEW_S:
            raise Rejected(401, "timestamp outside allowed skew")
        key = f"{tenant}\n{nonce}"
        for k in [k for k, exp in self._nonces.items() if exp < now]:
            del self._nonces[k]
        if key in self._nonces:
            raise Rejected(401, "replayed nonce")
        self._nonces[key] = now + 2 * MAX_SKEW_S
        return tenant

    def handle(self, headers, body: bytes) -> int:
        with self._lock:
            tenant = self._authenticate(headers, body)
            try:
                doc = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                raise Rejected(400, "body is not JSON")
            if not isinstance(doc, dict) or set(doc) != {"signals"} \
                    or not isinstance(doc["signals"], list):
                raise Rejected(400, 'body must be {"signals": [...]}')
            if len(doc["signals"]) > MAX_SIGNALS:
                raise Rejected(413, "too many signals in one batch")
            now = self.clock()
            sigs = [validate_signal(d, tenant, now, self.max_age_s)
                    for d in doc["signals"]]
            for s in sorted(sigs, key=lambda x: x.ts):
                for a in self.corr.ingest(s):
                    self._emit(a)
            return len(sigs)

    def _emit(self, a: SwarmAlert):
        if self._alerts_f:
            rec = asdict(a)
            rec["reason"] = a.reason
            self._alerts_f.write(json.dumps(rec) + "\n")
            self._alerts_f.flush()
        if self.on_alert:
            self.on_alert(a)
        else:
            print("SWARM", a.reason, a.tenants, file=sys.stderr)

    # -- lifecycle --------------------------------------------------------
    def serve_forever(self):
        self.httpd.serve_forever()

    def start_background(self):
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._alerts_f:
            self._alerts_f.close()


class _Server(ThreadingHTTPServer):
    """TLS handshake runs in the per-connection worker thread, not on the
    accept loop, so one slow or garbage client can't stall everyone else."""
    daemon_threads = True
    ssl_context: Optional[ssl.SSLContext] = None

    def finish_request(self, request, client_address):
        if self.ssl_context is not None:
            request.settimeout(15)
            try:
                tls = self.ssl_context.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            try:
                super().finish_request(tls, client_address)
            finally:
                tls.close()
            return
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        pass                                # no tracebacks for client resets


# ---------------------------------------------------------------------------
def push(url: str, tenant: str, secret: bytes, signals: List[TenantSignal],
         cafile: Optional[str] = None, timeout: float = 10.0,
         batch: int = MAX_SIGNALS) -> int:
    """Ship signals to the correlator. Returns how many were accepted; raises
    urllib.error.HTTPError on rejection."""
    if not url.startswith("https://"):
        host = urllib.request.urlparse(url).hostname or ""
        if not _is_loopback(host):
            raise ValueError("refusing to send signals over plain HTTP off loopback")
    ctx = ssl.create_default_context(cafile=cafile) if url.startswith("https://") else None
    accepted = 0
    for i in range(0, len(signals), batch):
        chunk = signals[i:i + batch]
        body = json.dumps({"signals": [asdict(s) for s in chunk]}).encode()
        ts, nonce = str(int(time.time())), secrets.token_hex(16)
        req = urllib.request.Request(
            url.rstrip("/") + "/v1/signals", data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "X-AW-Tenant": tenant, "X-AW-Timestamp": ts,
                     "X-AW-Nonce": nonce,
                     "X-AW-Signature": sign(secret, tenant, ts, nonce, body)})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            accepted += json.loads(r.read())["accepted"]
    return accepted


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_keys(path: str) -> Dict[str, bytes]:
    """Keys file: {"tenant-id": "<hex secret>", ...}. 32+ random bytes each,
    e.g. python3 -c 'import secrets; print(secrets.token_hex(32))'."""
    with open(path) as f:
        raw = json.load(f)
    keys = {t: bytes.fromhex(s) for t, s in raw.items()}
    short = [t for t, k in keys.items() if len(k) < 16]
    if short:
        raise ValueError(f"secret shorter than 16 bytes for: {short}")
    return keys


def main(argv=None):
    ap = argparse.ArgumentParser(description="AgentWall cross-tenant correlator transport")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the central correlator")
    s.add_argument("--keys", required=True, help="JSON {tenant: hex secret}")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--cert"); s.add_argument("--key")
    s.add_argument("--alerts", default="swarm_alerts.jsonl")
    s.add_argument("--min-tenants", type=int, default=3)
    s.add_argument("--window-s", type=float, default=86400.0)
    s.add_argument("--insecure-http", action="store_true",
                   help="allow plain HTTP on a non-loopback address (don't)")

    p = sub.add_parser("push", help="extract signals from a log and send them")
    p.add_argument("logfile")
    p.add_argument("--url", required=True)
    p.add_argument("--tenant", required=True)
    p.add_argument("--secret-file", required=True, help="file holding the hex secret")
    p.add_argument("--salt", default="", help="actor-hash salt shared by all tenants")
    p.add_argument("--cafile", help="CA bundle to trust (e.g. a private CA)")
    p.add_argument("--format", default="auto", choices=["auto", "nginx", "cloudflare", "jsonl"])
    a = ap.parse_args(argv)

    if a.cmd == "serve":
        ctx = None
        if a.cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(a.cert, a.key)
        elif not _is_loopback(a.host) and not a.insecure_http:
            ap.error("--cert/--key required to listen off loopback")
        svc = CorrelatorService(
            load_keys(a.keys), a.host, a.port, ctx,
            CrossTenantCorrelator(window_s=a.window_s, min_tenants=a.min_tenants),
            alerts_path=a.alerts)
        print(f"correlator on {'https' if ctx else 'http'}://{a.host}:{svc.port} "
              f"({len(svc.keys)} tenants) -> {a.alerts}", file=sys.stderr)
        try:
            svc.serve_forever()
        except KeyboardInterrupt:
            svc.stop()
        return 0

    from ingest import parse_file
    with open(a.secret_file) as f:
        secret = bytes.fromhex(f.read().strip())
    sigs = extract_signals(parse_file(a.logfile, a.format), a.tenant, salt=a.salt)
    try:
        n = push(a.url, a.tenant, secret, sigs, cafile=a.cafile)
    except urllib.error.HTTPError as e:
        print(f"rejected: {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    print(f"{len(sigs)} signals extracted, {n} accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
