#!/usr/bin/env python3
"""
Log ingest shim: turn REAL web logs into Event records and run the detectors.

Supported inputs (auto-detected per line):
  - nginx/apache "combined" access log
  - Cloudflare Logpush JSON (one JSON object per line)
  - this PoC's own JSONL dump (events_to_jsonl)

Usage:
    python3 ingest.py ACCESS_LOG [--format auto|nginx|cloudflare|jsonl]
                                 [--body-field name] [--json]

Notes / honesty:
  * Inbound access logs do NOT contain egress destinations, so the
    egress/dead-drop detector needs a separate firewall / egress-proxy feed.
    Point --format jsonl at a dump that includes egress rows for that.
  * Request BODIES are rarely in access logs. The injection prompt-leak check
    only works if your pipeline samples bodies into a field (pass its name
    with --body-field). The canary-callback check works from the URL alone,
    so it works on any access log once you've seeded canary docs.
  * truth is unknown for real logs, so this prints detections, not scores.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Iterator, Optional

from events import Event
from detectors import (run_detectors, BlockDefianceDetector,
                       InjectionTripwireDetector, EgressDeadDropDetector)

# nginx combined:
# 1.2.3.4 - - [24/Oct/2026:11:34:56 +1000] "GET /path HTTP/1.1" 200 1234 "ref" "UA"
_NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ ]+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')

_NGINX_TS = "%d/%b/%Y:%H:%M:%S %z"


def _to_epoch(ts: str, fmt: str) -> float:
    from datetime import datetime
    try:
        return datetime.strptime(ts, fmt).timestamp()
    except Exception:
        return 0.0


def parse_nginx(line: str, body_field: Optional[str] = None) -> Optional[Event]:
    m = _NGINX_RE.search(line)
    if not m:
        return None
    g = m.groupdict()
    return Event(
        ts=_to_epoch(g["ts"], _NGINX_TS),
        session_id=g["ip"] + "|" + g["ua"],  # no session id: IP+UA pseudo-session
        src_ip=g["ip"], user_agent=g["ua"],
        method=g["method"], path=g["path"],
        status=int(g["status"]),
        bytes_out=0 if g["bytes"] == "-" else int(g["bytes"]),
        has_referer=bool(g["ref"] and g["ref"] != "-"),
        truth="unknown")


def parse_cloudflare(line: str, body_field: Optional[str] = None) -> Optional[Event]:
    try:
        o = json.loads(line)
    except Exception:
        return None
    # Cloudflare field names vary by dataset; map the common ones.
    ts = o.get("EdgeStartTimestamp") or o.get("Datetime") or 0
    if isinstance(ts, str):
        # RFC3339 -> epoch
        from datetime import datetime
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            ts = 0.0
    elif isinstance(ts, (int, float)) and ts > 1e15:
        ts = ts / 1e9  # nanoseconds
    body = ""
    if body_field and body_field in o:
        body = str(o[body_field])[:512]
    return Event(
        ts=float(ts),
        # RayID is unique PER REQUEST, so it can't be a session key.
        session_id=str(o.get("ClientIP", "?")) + "|" + str(o.get("ClientRequestUserAgent", "")),
        src_ip=o.get("ClientIP", "?"),
        user_agent=o.get("ClientRequestUserAgent", ""),
        method=o.get("ClientRequestMethod", "GET"),
        path=o.get("ClientRequestURI", o.get("ClientRequestPath", "/")),
        status=int(o.get("EdgeResponseStatus", o.get("OriginResponseStatus", 0)) or 0),
        bytes_out=int(o.get("EdgeResponseBytes", 0) or 0),
        body_sample=body,
        has_referer=bool(o.get("ClientRequestReferer")),
        web_bot_auth=bool(o.get("VerifiedBotCategory") or o.get("WebBotAuth")),
        truth="unknown")


def parse_jsonl(line: str, body_field: Optional[str] = None) -> Optional[Event]:
    try:
        o = json.loads(line)
    except Exception:
        return None
    o.pop("truth", None)  # ignore any label; real-mode is unlabelled
    allowed = Event.__dataclass_fields__.keys()
    return Event(**{k: v for k, v in o.items() if k in allowed}, truth="unknown")


_PARSERS = {"nginx": parse_nginx, "cloudflare": parse_cloudflare,
            "jsonl": parse_jsonl}


def _detect_format(line: str) -> str:
    s = line.lstrip()
    if s.startswith("{"):
        try:
            o = json.loads(s)
            return "cloudflare" if "ClientRequestURI" in o or "RayID" in o else "jsonl"
        except Exception:
            return "jsonl"
    return "nginx"


def parse_file(path: str, fmt: str = "auto",
               body_field: Optional[str] = None) -> Iterator[Event]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            use = fmt if fmt != "auto" else _detect_format(line)
            ev = _PARSERS[use](line, body_field)
            if ev:
                yield ev


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run AgentWall detectors on real logs")
    ap.add_argument("logfile")
    ap.add_argument("--format", default="auto",
                    choices=["auto", "nginx", "cloudflare", "jsonl"])
    ap.add_argument("--body-field", default=None,
                    help="JSON field holding a sampled request body (injection leak check)")
    ap.add_argument("--allowlist", default=None,
                    help="comma-separated known-good egress hosts (for jsonl egress rows)")
    ap.add_argument("--json", action="store_true", help="emit detections as JSONL")
    args = ap.parse_args(argv)

    events = list(parse_file(args.logfile, args.format, args.body_field))
    events.sort(key=lambda e: e.ts)
    if not events:
        print("No parseable log lines found. Check --format.", file=sys.stderr)
        return 2

    allow = set((args.allowlist or "").split(",")) - {""}
    detectors = [BlockDefianceDetector(), InjectionTripwireDetector(),
                 EgressDeadDropDetector(allowlist=allow)]
    dets = run_detectors(events, detectors)

    if args.json:
        for d in dets:
            print(json.dumps({"detector": d.detector, "ts": d.ts,
                              "session": d.session_id, "src_ip": d.src_ip,
                              "severity": d.severity, "reason": d.reason}))
    else:
        print(f"parsed {len(events)} events, "
              f"{len({e.session_id for e in events})} sessions/IPs")
        print(f"{len(dets)} detections:\n")
        for d in dets:
            print(f"  [{d.severity:6}] {d.detector:18} {d.src_ip:16} {d.reason}")
        if not dets:
            print("  (none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
