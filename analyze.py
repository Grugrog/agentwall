#!/usr/bin/env python3
"""
Summarise an AgentWall honeypot/access log (JSONL of Event records) and run the
detectors over it. Reusable on the honeypot's own log or any ingested log.

Usage: python3 analyze.py honeypot_live.jsonl
"""
from __future__ import annotations

import collections
import json
import sys

from events import Event
from detectors import run_detectors, _actor_cluster, _resource_key


def load(path):
    out = []
    allowed = Event.__dataclass_fields__.keys()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            out.append(Event(**{k: v for k, v in o.items() if k in allowed},
                             truth="unknown"))
    out.sort(key=lambda e: e.ts)
    return out


def main(path):
    ev = load(path)
    if not ev:
        print("empty log"); return

    status = collections.Counter(e.status for e in ev)
    actors = collections.Counter(_actor_cluster(e) for e in ev)
    uas = collections.Counter((e.user_agent or "")[:40] for e in ev)
    denied = [e for e in ev if e.denied]
    callbacks = [e for e in ev if e.path.startswith("/cb/")]
    canary_fetch = [e for e in ev if e.path in (
        "/docs/internal-process.html", "/datasets/client-index.json",
        "/.well-known/ai-plugin.json")]
    span = ev[-1].ts - ev[0].ts

    print(f"=== honeypot log: {path} ===")
    print(f"events={len(ev)}  span={span:.1f}s  actors(/24)={len(actors)}")
    print(f"status mix: {dict(status.most_common())}")
    print(f"denials={len(denied)}  canary-fetches={len(canary_fetch)}  "
          f"callbacks={len(callbacks)}")
    print(f"top actors: {actors.most_common(5)}")
    print(f"top UAs: {[u for u,_ in uas.most_common(5)]}")

    dets = run_detectors(ev)
    bydet = collections.Counter(d.detector for d in dets)
    print(f"\ndetections={len(dets)}  by_detector={dict(bydet)}")
    for d in dets:
        extra = []
        if d.actor_type: extra.append(f"actor={d.actor_type}")
        if d.signature: extra.append(f"grammar={d.signature}")
        if getattr(d, "confidence", ""): extra.append(d.confidence)
        tail = ("  {" + ", ".join(extra) + "}") if extra else ""
        print(f"  [{d.severity:8}] {d.detector:18} {d.reason}{tail}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "honeypot_live.jsonl")
