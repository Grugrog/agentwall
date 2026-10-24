#!/usr/bin/env python3
"""
Launch the honeypot locally, fire REAL HTTP traffic at it (benign + agent-like
clients over the loopback), then run the detectors on the server's OWN captured
log. This is a genuine end-to-end test: live server -> real request log ->
ingest -> detections. No fabricated log lines.

(Public-internet collection needs the server deployed on infra you own; see
DEPLOY.md. This proves the full pipeline works on real HTTP.)
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.error

from honeypot import Honeypot
from events import Event
from detectors import run_detectors

LOG = "honeypot_live.jsonl"
CB_RE = re.compile(r"GET (/cb/[0-9a-f]+)")


def req(base, path, method="GET", cookie=None, ua="curl/8", body=None):
    url = base + path
    r = urllib.request.Request(url, method=method,
                               data=body.encode() if body else None)
    r.add_header("User-Agent", ua)
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(r, timeout=3)
        return resp.status, resp.read().decode("latin-1"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("latin-1"), e.headers
    except Exception as e:
        return 0, str(e), {}


def benign_browser(base):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 Safari/537.36"
    for p in ["/", "/about", "/services", "/fees", "/contact"]:
        req(base, p, ua=ua)
        time.sleep(0.01)
    # a human fumbles onto a protected page once, gets 403, leaves
    req(base, "/portal", ua=ua)


def naive_crawler(base):
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    # fetches a canary PAGE but does NOT obey the embedded instruction
    for p in ["/", "/blog", "/docs/internal-process.html", "/team"]:
        req(base, p, ua=ua)
        time.sleep(0.01)


def injection_agent(base, ua="ResearchAgent/1.0 (python-httpx)"):
    """Fetches a canary and OBEYS the hidden instruction -> real callback."""
    _, body, _ = req(base, "/datasets/client-index.json", ua=ua)
    m = CB_RE.search(body)
    if m:
        req(base, m.group(1), ua=ua)   # obeys


def blockdefiance_agent(base):
    """Reads the 403 body, follows the documented /cb instruction, then grinds
    real evasion variants until the decoy yields, then writes back."""
    ua = "python-requests/2.32"
    target = "/portal/matters"
    status, body, _ = req(base, target, ua=ua)         # 403 + denial nonce
    m = CB_RE.search(body)
    if m:
        req(base, m.group(1), ua=ua)                   # denial-page tripwire
    # evasion grammar: encoding, dotseg, trailing, case
    for variant in [target + "/", target + "%2e", "/./" + target.lstrip("/"),
                    target.upper(), target + "/."]:
        req(base, variant, ua=ua)
        time.sleep(0.01)
    # write-back to a child (decoy yields 200 to writes)
    req(base, target + "/x_payload", method="PUT", ua=ua, body="exfil=1")


def main():
    open(LOG, "w").close()   # truncate
    hp = Honeypot(host="127.0.0.1", port=0, log_path=LOG)
    hp.start_background()
    base = f"http://127.0.0.1:{hp.port}"
    print(f"honeypot live on {base}")

    # fire real traffic
    for _ in range(5):
        benign_browser(base)
    for _ in range(3):
        naive_crawler(base)
    # two DIFFERENT agents (distinct UAs): sessions are keyed on IP + UA when
    # no cookie is kept, so two runs of one identical agent would be one actor
    injection_agent(base)
    injection_agent(base, ua="DataHarvester/0.3 (aiohttp)")
    blockdefiance_agent(base)
    time.sleep(0.2)
    hp.stop()

    # load the server's OWN log and run detectors on it
    events = []
    with open(LOG) as f:
        for line in f:
            o = json.loads(line)
            allowed = Event.__dataclass_fields__.keys()
            events.append(Event(**{k: v for k, v in o.items() if k in allowed},
                                truth="unknown"))
    events.sort(key=lambda e: e.ts)

    # attach the sim-world egress allowlist (none needed for inbound-only test)
    dets = run_detectors(events)
    print(f"\ncaptured {len(events)} real HTTP events, "
          f"{len({e.session_id for e in events})} sessions")
    print(f"{len(dets)} detections from live traffic:\n")
    for d in dets:
        extra = []
        if d.actor_type: extra.append(f"actor={d.actor_type}")
        if d.signature: extra.append(f"grammar={d.signature}")
        if getattr(d, "confidence", ""): extra.append(d.confidence)
        tail = ("  {" + ", ".join(extra) + "}") if extra else ""
        print(f"  [{d.severity:8}] {d.detector:18} {d.reason}{tail}")
    if not dets:
        print("  (none)")


if __name__ == "__main__":
    main()
