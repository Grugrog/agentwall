"""
Cross-tenant correlation — the piece no incumbent sells and the only real moat.

The distributed-agent problem (arXiv 2605.31593): a swarm splits its work so
each target sees only one or two quiet probes. No single site's detector fires
(correctly — one probe isn't an attack). The campaign is only visible ACROSS
targets. A solo site can't see it; a multi-tenant operator can.

How it works, privacy-first:
  1. Each tenant's local detector observes post-deny grinds — INCLUDING ones
     below its own firing threshold (a deny + a couple of evasion variants,
     no breakthrough). For each, it emits a SIGNAL that carries NO customer
     data: only a hash of (evasion-grammar + resource-shape-category), a
     hashed actor (so the same source can be counted without revealing it),
     a coarse timestamp, and the tenant id. Raw paths, query strings, bodies
     and real IPs never leave the tenant.
  2. A central correlator buckets signals by the grammar/shape digest within a
     sliding window. When the SAME digest appears across >= min_tenants
     distinct tenants, it fires a swarm alert — even though each tenant saw
     too little to alarm locally.

The correlation key is the evasion GRAMMAR (ordered mutation classes), a
behavioural fingerprint of the tool/agent. A swarm driven by one agent leaves
the same grammar at every victim; benign noise does not line up across
unrelated tenants.

This module is transport-agnostic: in production tenants POST signals to the
correlator over TLS. Here it's an in-process class for the PoC.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from events import Event
from detectors import (_actor_cluster, _resource_key, _classify_mutation,
                       HARD_EVASION)


# ---------------------------------------------------------------------------
# Resource shape: generalise a resource key to a category + depth so tenants
# with DIFFERENT real paths still correlate on structure, while leaking
# nothing specific. '/portal/matters' and '/client-area/files' both at depth 2
# behind an auth wall share the shape 'auth|d2'.
_CATEGORY = {
    "portal": "auth", "login": "auth", "account": "auth", "admin": "admin",
    "api": "api", "reports": "data", "report": "data", "data": "data",
    "export": "data", "datasets": "data", "statistics": "data",
}


def _resource_shape(resource_key: str) -> str:
    segs = [s for s in resource_key.split("/") if s]
    depth = len(segs)
    head = segs[0] if segs else ""
    cat = _CATEGORY.get(head, "other")
    return f"{cat}|d{depth}"


def _digest(signature: str, shape: str) -> str:
    """Stable, non-reversible correlation key. Equal (grammar, shape) across
    tenants -> equal digest, so the correlator can match without ever seeing
    the underlying paths."""
    return hashlib.sha256(f"{signature}::{shape}".encode()).hexdigest()[:16]


def _digest_grammar(signature: str) -> str:
    """Grammar-only key: correlates the same TTP across DIFFERENT endpoint
    types (a swarm hitting /portal at one firm and /admin at another). Broader
    than grammar+shape, so it uses a higher tenant threshold."""
    return hashlib.sha256(f"G::{signature}".encode()).hexdigest()[:16]


def _hash_actor(actor: str, salt: str = "") -> str:
    return hashlib.sha256((salt + "|" + actor).encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
@dataclass
class TenantSignal:
    """What a tenant emits per observed grind. Contains NO raw customer data."""
    tenant_id: str
    ts: float
    digest: str                 # sha256(grammar :: shape)[:16]
    signature: str              # human-readable grammar, e.g. "encoding,dotseg"
    shape: str                  # e.g. "auth|d2"
    actor_hash: str             # hashed source /24 (counts sources, hides them)
    hard: bool                  # did the grammar include a hard-evasion class?
    reached_breakthrough: bool  # did this grind break through locally?


@dataclass
class SwarmAlert:
    digest: str
    signature: str
    shape: str
    tenants: List[str]
    distinct_actors: int
    total_signals: int
    first_ts: float
    last_ts: float
    scope: str = "grammar+shape"    # or "grammar" (broader, cross-endpoint)

    @property
    def reason(self) -> str:
        span = self.last_ts - self.first_ts
        where = self.shape if self.scope == "grammar+shape" else "mixed endpoints"
        return (f"cross-tenant swarm [{self.scope}]: grammar [{self.signature}] "
                f"on {where} seen at {len(self.tenants)} tenants "
                f"({self.distinct_actors} distinct sources) over {span/3600:.1f}h "
                f"-- distributed campaign below any single site's threshold")


# ---------------------------------------------------------------------------
def extract_signals(events: Iterable[Event], tenant_id: str,
                    salt: str = "", min_variants: int = 2) -> List[TenantSignal]:
    """Walk one tenant's events and emit a signal for every post-deny grind,
    INCLUDING sub-threshold ones (>= min_variants distinct evasion variants,
    breakthrough or not). This is deliberately more sensitive than the local
    alerting detector -- the whole point is to ship the quiet stuff to the hive.
    """
    # per (actor, resource): accumulate variants + ordered grammar since deny
    state: Dict[Tuple[str, str], dict] = {}
    emitted: set = set()
    out: List[TenantSignal] = []

    def maybe_emit(key, st, ts, broke):
        variants = len(st["variants"])
        if variants < min_variants:
            return
        # build de-duplicated-consecutive grammar signature
        sig_parts, prev = [], None
        for g in st["grammar"]:
            if g != prev and g != "same":
                sig_parts.append(g)
            prev = g
        signature = ",".join(sig_parts)
        if not signature:
            return
        shape = _resource_shape(key[1])
        dig = _digest(signature, shape)
        ekey = (key, dig, broke)
        if ekey in emitted:
            return
        emitted.add(ekey)
        hard = bool(set(st["grammar"]) & HARD_EVASION)
        out.append(TenantSignal(
            tenant_id=tenant_id, ts=ts, digest=dig, signature=signature,
            shape=shape, actor_hash=_hash_actor(key[0], salt), hard=hard,
            reached_breakthrough=broke))

    for e in events:
        if e.direction != "inbound":
            continue
        rk = _resource_key(e.path)
        actor = _actor_cluster(e)
        key = (actor, rk)
        if e.denied:
            st = state.get(key)
            if not st:
                st = state[key] = {"variants": set(), "grammar": [],
                                   "orig_path": e.path, "orig_method": e.method,
                                   "first_ts": e.ts}
            st["variants"].add(e.path.lower())
            cls = _classify_mutation(st["orig_path"], st["orig_method"],
                                     e.path, e.method)
            st["grammar"].append(cls)
            continue
        st = state.get(key)
        if not st:
            continue
        # a post-deny non-deny event: record the mutation + maybe a breakthrough
        st["variants"].add(e.path.lower())
        cls = _classify_mutation(st["orig_path"], st["orig_method"],
                                 e.path, e.method)
        st["grammar"].append(cls)
        broke = e.ok or e.method in ("PUT", "POST", "PATCH", "DELETE")
        maybe_emit(key, st, e.ts, broke)
    # also emit deny-only grinds (no following success) at end of stream
    for key, st in state.items():
        maybe_emit(key, st, st["first_ts"], False)
    return out


class CrossTenantCorrelator:
    def __init__(self, window_s: float = 86400.0, min_tenants: int = 3,
                 min_tenants_grammar: Optional[int] = None,
                 require_hard: bool = True):
        # require_hard: only correlate grammars that contain a hard-evasion
        # class. Stops benign cross-tenant noise (everyone's stray trailing
        # slash) from ever lining up into a false swarm.
        # Two tiers run together:
        #   grammar+shape -> min_tenants (precise; same TTP + same endpoint type)
        #   grammar-only  -> min_tenants_grammar (broader; same TTP, any endpoint)
        self.window_s = window_s
        self.min_tenants = min_tenants
        self.min_tenants_grammar = (min_tenants_grammar
                                    if min_tenants_grammar is not None
                                    else min_tenants + 1)
        self.require_hard = require_hard
        self._buckets_shape: Dict[str, List[TenantSignal]] = defaultdict(list)
        self._buckets_grammar: Dict[str, List[TenantSignal]] = defaultdict(list)
        self._fired: set = set()

    def _check(self, bucket: List[TenantSignal], sig: TenantSignal, key: str,
               threshold: int, scope: str) -> Optional[SwarmAlert]:
        bucket.append(sig)
        bucket[:] = [s for s in bucket if sig.ts - s.ts <= self.window_s]
        tenants = {s.tenant_id for s in bucket}
        fire_key = (scope, key)
        if len(tenants) >= threshold and fire_key not in self._fired:
            self._fired.add(fire_key)
            return SwarmAlert(
                digest=key, signature=sig.signature, shape=sig.shape,
                tenants=sorted(tenants),
                distinct_actors=len({s.actor_hash for s in bucket}),
                total_signals=len(bucket),
                first_ts=min(s.ts for s in bucket),
                last_ts=max(s.ts for s in bucket), scope=scope)
        return None

    def ingest(self, sig: TenantSignal) -> List[SwarmAlert]:
        """Streaming entry point. One signal can complete both tiers at once,
        so this returns every alert it raised (0, 1 or 2) -- returning only the
        first would silently lose the other, since it is already marked fired."""
        if self.require_hard and not sig.hard:
            return []
        alerts = []
        # precise tier first (grammar+shape), then broad (grammar-only)
        a = self._check(self._buckets_shape[sig.digest], sig, sig.digest,
                        self.min_tenants, "grammar+shape")
        if a:
            alerts.append(a)
        gkey = _digest_grammar(sig.signature)
        b = self._check(self._buckets_grammar[gkey], sig, gkey,
                        self.min_tenants_grammar, "grammar")
        if b:
            alerts.append(b)
        return alerts

    def ingest_many(self, sigs: Iterable[TenantSignal]) -> List[SwarmAlert]:
        alerts = []
        for s in sorted(sigs, key=lambda x: x.ts):
            alerts.extend(self.ingest(s))
        return alerts
