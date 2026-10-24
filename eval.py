"""
Eval harness for the AgentWall PoC.

Scoring is at the SESSION level, because that's the unit an analyst acts on:
"is this session an attack, yes/no". A session is:
  - a true positive  if it contains >=1 attacker event AND we fired on it
  - a false negative  if it's an attack session and we never fired
  - a false positive  if it's a human/goodbot session and we fired
  - a true negative    if it's benign and we stayed quiet

We report overall and PER ATTACK TYPE (block-defiance, low-and-slow,
injection) because an aggregate number hides which vector we miss. We also
report time-to-detect: seconds from the session's first attacker event to the
first detection on it.

Run across multiple seeds to show the numbers are stable, not a lucky draw.
"""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev
from typing import Dict, List

from events import Event
from detectors import run_detectors, BlockDefianceDetector, InjectionTripwireDetector
from simulator import Simulator, CANARY_PATHS, CALLBACK_PREFIX, PROTECTED_PATHS


def _session_truth(events: List[Event]) -> Dict[str, str]:
    """session_id -> 'attacker' if any attacker event else its benign label."""
    truth: Dict[str, str] = {}
    for e in events:
        if e.session_id not in truth:
            truth[e.session_id] = e.truth
        if e.truth == "attacker":
            truth[e.session_id] = "attacker"
    return truth


def _session_subtype(events: List[Event]) -> Dict[str, str]:
    """Label each attacker session by vector, for per-type recall.

    Heuristic on the generated events (NOT used by detectors):
      injection   -> session touched a canary path or callback
      low_and_slow / block_defiance -> had a deny; pace decides which
    """
    by_sess: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        by_sess[e.session_id].append(e)
    sub: Dict[str, str] = {}
    for sid, evs in by_sess.items():
        if not any(e.truth == "attacker" for e in evs):
            continue
        paths = [e.path for e in evs]
        if any(p in CANARY_PATHS or p.startswith(CALLBACK_PREFIX) for p in paths):
            sub[sid] = "injection"
            continue
        # timing between the deny and the next attempt: slow => low_and_slow
        denies = [e for e in evs if e.denied]
        gaps = []
        evs_sorted = sorted(evs, key=lambda e: e.ts)
        for a, b in zip(evs_sorted, evs_sorted[1:]):
            gaps.append(b.ts - a.ts)
        med_gap = sorted(gaps)[len(gaps) // 2] if gaps else 0
        sub[sid] = "low_and_slow" if med_gap > 1.5 else "block_defiance"
    return sub


def evaluate(events: List[Event]):
    truth = _session_truth(events)
    subtype = _session_subtype(events)
    detections = run_detectors(events)

    fired_sessions = defaultdict(list)   # sid -> [Detection]
    for d in detections:
        fired_sessions[d.session_id].append(d)

    # first attacker-event ts per session, for time-to-detect
    first_atk_ts: Dict[str, float] = {}
    for e in events:
        if e.truth == "attacker" and e.session_id not in first_atk_ts:
            first_atk_ts[e.session_id] = e.ts

    tp = fp = fn = tn = 0
    ttd: List[float] = []
    per_type_total = defaultdict(int)
    per_type_hit = defaultdict(int)
    fp_detail = defaultdict(int)  # which detector caused benign fires

    for sid, label in truth.items():
        fired = sid in fired_sessions
        if label == "attacker":
            per_type_total[subtype.get(sid, "unknown")] += 1
            if fired:
                tp += 1
                per_type_hit[subtype.get(sid, "unknown")] += 1
                first_det = min(d.ts for d in fired_sessions[sid])
                ttd.append(first_det - first_atk_ts[sid])
            else:
                fn += 1
        else:  # benign
            if fired:
                fp += 1
                for d in fired_sessions[sid]:
                    fp_detail[d.detector] += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "fpr": fpr, "f1": f1,
        "ttd_mean": mean(ttd) if ttd else 0.0,
        "ttd_max": max(ttd) if ttd else 0.0,
        "per_type": {k: (per_type_hit[k], per_type_total[k]) for k in per_type_total},
        "fp_detail": dict(fp_detail),
        "n_sessions": len(truth),
        "n_detections": len(detections),
    }


def _fmt_pct(x): return f"{100*x:5.1f}%"


def run_multi(seeds=range(1, 11)):
    rows = []
    for s in seeds:
        ev = Simulator(seed=s).run()
        rows.append(evaluate(ev))

    print("=" * 66)
    print("AgentWall PoC -- web/HTTP detectors, session-level eval")
    print(f"seeds: {list(seeds)}   (benign = human+goodbot, attack = 3 vectors)")
    print("=" * 66)

    def col(key): return [r[key] for r in rows]

    print("\nOverall (mean +/- stdev across seeds):")
    for label, key in [("recall (attack caught)", "recall"),
                       ("precision", "precision"),
                       ("false-positive rate", "fpr"),
                       ("F1", "f1")]:
        vals = col(key)
        print(f"  {label:26s} {_fmt_pct(mean(vals))}  +/- {_fmt_pct(pstdev(vals))}")

    print("\nTime-to-detect (seconds from first attacker event):")
    print(f"  mean {mean(col('ttd_mean')):.2f}s   worst-seed max {max(col('ttd_max')):.2f}s")

    print("\nRecall by attack vector (caught / total, summed over seeds):")
    agg_hit = defaultdict(int); agg_tot = defaultdict(int)
    for r in rows:
        for k, (h, t) in r["per_type"].items():
            agg_hit[k] += h; agg_tot[k] += t
    for k in sorted(agg_tot):
        h, t = agg_hit[k], agg_tot[k]
        print(f"  {k:16s} {h:4d} / {t:4d}   {_fmt_pct(h/t if t else 0)}")

    print("\nFalse positives by detector (summed over seeds):")
    agg_fp = defaultdict(int)
    for r in rows:
        for k, v in r["fp_detail"].items():
            agg_fp[k] += v
    total_benign = sum(r["tn"] + r["fp"] for r in rows)
    if agg_fp:
        for k, v in sorted(agg_fp.items()):
            print(f"  {k:20s} {v} fires  ({_fmt_pct(v/total_benign)} of benign sessions)")
    else:
        print(f"  none -- 0 / {total_benign} benign sessions flagged")

    print("\nTotals (summed): "
          f"TP={sum(col('tp'))} FP={sum(col('fp'))} "
          f"FN={sum(col('fn'))} TN={sum(col('tn'))}")
    print("=" * 66)
    return rows


if __name__ == "__main__":
    run_multi()
