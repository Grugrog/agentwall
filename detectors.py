"""
Detectors for the AgentWall PoC.

Two production-shaped detectors, both streaming (process one Event at a time,
keep bounded per-session state). Neither reads Event.truth.

  BlockDefianceDetector
      The core signal from both the Hugging Face and Medicare postmortems:
      a client is DENIED, then within a short window makes several ALTERNATE
      attempts (different path encodings / methods against the same resource)
      and eventually SUCCEEDS -- often followed by a write. Humans don't do
      this; when a human is denied they leave. Good bots respect the deny.

      Fires when, within one session and a sliding time window:
        (deny on resource R) THEN (>= K distinct alternate attempts at R)
        THEN (a 2xx on an R-variant OR a write method on R).
      The "alternate attempts after a deny then success" ordering is what
      keeps false positives off humans who merely hit one 403.

  InjectionTripwireDetector
      Catches the poisoned-input / indirect-injection vector. Two independent
      triggers, either is sufficient:
        (a) CANARY CALLBACK: any request to the /cb/ callback space. These
            URLs appear only inside seeded decoy docs as a hidden instruction,
            so a hit means something *read and obeyed* that instruction. Near
            zero false-positive by construction.
        (b) PROMPT LEAK: an LLM artifact string surfaced in a request body or
            odd header -- an agent spilling its own scratchpad into traffic.

Severity + reason strings are written to be dropped straight into an alert /
report.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional

from events import Event, Detection


_VER_RE = re.compile(r"/v(\d+)(/|$)")

# Grammar classes that indicate DELIBERATE bypass engineering, as opposed to
# incidental browser/user noise (a stray trailing slash or ?utm= query).
# Benign users behind one NAT /24 produce at most {trailing, route, same};
# only a client actively engineering its way past a block produces these.
HARD_EVASION = {"encoding", "dotseg", "case", "method", "version"}


def _classify_mutation(orig_path: str, orig_method: str,
                       path: str, method: str) -> str:
    """Classify ONE evasion attempt relative to the originally-denied request.

    Returns a short transform-class token. The ordered sequence of these
    across a grind is the 'evasion grammar' -- a fingerprint of HOW the client
    tried to get around the block. Scanners emit a long, fixed-order grammar
    (they walk a hardcoded list); agents emit a short, contextually-relevant
    one (they reason about a few plausible routes).
    """
    op = orig_path.split("?", 1)[0].split("#", 1)[0]
    p = path.split("?", 1)[0].split("#", 1)[0]
    if method != orig_method:
        return "method"                       # GET -> POST/PUT/HEAD
    # version sibling: /api/v1 -> /api/v2
    mo, mp = _VER_RE.search(op), _VER_RE.search(p)
    if mo and mp and mo.group(1) != mp.group(1):
        return "version"
    if "%2e" in path.lower() or "%2f" in path.lower() or "%25" in path.lower():
        return "encoding"
    if "/./" in path or "/../" in path or path.startswith("/.."):
        return "dotseg"
    if p.rstrip("/") == op.rstrip("/") and p != op:
        return "trailing"                     # trailing slash only
    if path != orig_path and (path.endswith("#") or path.endswith(".") or
                              "?" in path or path.endswith(";")):
        return "trailing"                     # trailing junk char
    if p.lower() == op.lower() and p != op:
        return "case"                         # case-flip only
    low_op, low_p = op.lower().rstrip("/"), p.lower().rstrip("/")
    if low_p != low_op:
        # different path entirely -> route discovery (looking for a sibling
        # endpoint: /export, /statistics, /download, a docs route, etc.)
        return "route"
    return "same"                             # identical retry


def _timing_regularity(ts_list: list) -> float:
    """Coefficient of variation of gaps (std/mean). Low = metronomic (script),
    higher = irregular (reasoning agent/human). Returned for reporting only."""
    gaps = [b - a for a, b in zip(ts_list, ts_list[1:]) if b >= a]
    if len(gaps) < 2:
        return 0.0
    m = sum(gaps) / len(gaps)
    if m == 0:
        return 0.0
    var = sum((g - m) ** 2 for g in gaps) / len(gaps)
    return (var ** 0.5) / m


def _classify_timing(ts_list: list) -> str:
    """Infer the actor behind a post-deny grind from inter-attempt gaps.

      script     -- fires variants in milliseconds (median gap < 0.25s). A
                    classic bypass-403 tool walking a fixed list.
      agent      -- LLM 'think gap' between attempts: ~0.3s..45s, and not
                    perfectly periodic. The tell that it's reasoning, not a
                    hardcoded loop.
      human-like -- slow and irregular (median gap > 45s). Unusual for a grind;
                    lowers confidence that this is automation at all.
    This only sharpens the LABEL in the report; it never gates a detection.
    """
    gaps = [b - a for a, b in zip(ts_list, ts_list[1:]) if b >= a]
    if len(gaps) < 2:
        return ""  # not enough signal
    gaps.sort()
    med = gaps[len(gaps) // 2]
    if med < 0.25:
        return "script"
    if med <= 45.0:
        return "agent"
    return "human-like"


# ---------------------------------------------------------------------------
def _actor_cluster(e: Event) -> str:
    """A coarse, stable actor identity that survives session rotation.

    An attacker who spaces attempts across many short sessions (or rotates
    session cookies) defeats a per-session detector. Clustering on the source
    /24 re-links those attempts. In production this is upgraded to ASN or a
    JA4H/header-order hash; /24 is the zero-dependency version.
    """
    ip = e.src_ip or "?"
    parts = ip.split(".")
    if len(parts) == 4:
        return "net:" + ".".join(parts[:3]) + ".0/24"
    return "ip:" + ip


# ---------------------------------------------------------------------------
def _resource_key(path: str) -> str:
    """Collapse a path and its evasion variants to the resource they target.

    /portal, /PORTAL, /portal/, /portal%2e, /./portal, /../portal, /portal?x
    all map to 'portal'. This is how we tell 'same resource, new trick' from
    'genuinely different page'.
    """
    p = path.split("?", 1)[0].split("#", 1)[0]
    p = p.lower()
    # decode the common evasion encodings BEFORE splitting
    p = p.replace("%2e", ".").replace("%2f", "/").replace("%252e", ".")
    p = p.replace("/./", "/")
    # drop ALL dot / traversal / empty segments anywhere in the path, and
    # trailing-dot tricks like 'matters.' -> 'matters'. This is the whole
    # job of the normaliser: make every evasion variant of a resource map to
    # the same key, so the deny and the breakthrough land in one bucket.
    segs = []
    for s in p.split("/"):
        s = s.rstrip(".")           # 'matters.' -> 'matters'
        if s in ("", ".", ".."):
            continue
        # fold an API version segment so /api/v1/x and /api/v2/x share a key:
        # version-probing is 'same resource, new trick', not a new resource.
        if re.fullmatch(r"v\d+", s):
            s = "v*"
        segs.append(s)
    # take up to the first THREE meaningful segments. Two is too coarse once a
    # version is folded (/api/v*/matters vs /api/v*/clients must stay distinct).
    return "/".join(segs[:3])


class BlockDefianceDetector:
    name = "block_defiance"

    def __init__(self, window_s: float = 60.0, min_alternates: int = 3,
                 min_attempts: int = 5, max_window_s: float = 600.0,
                 actor_window_s: float = 3600.0, actor_max_window_s: float = 86400.0):
        # Two scopes run in parallel:
        #   FAST  -- keyed on (session, resource). Short sliding window
        #            (window_s), hard cap max_window_s. Catches the burst grind.
        #   SLOW  -- keyed on (actor_cluster, resource). Long idle window
        #            (actor_window_s, default 1h) and long cap (default 24h).
        #            Catches a patient grind spread across sessions or beyond
        #            the fast window -- the idle-window gap we had before.
        # A breakthrough fires from whichever scope is armed; alerts dedupe on
        # (actor_cluster, resource) so one campaign = one alert.
        self.window_s = window_s
        self.max_window_s = max_window_s
        self.min_alternates = min_alternates
        self.min_attempts = min_attempts
        self.actor_window_s = actor_window_s
        self.actor_max_window_s = actor_max_window_s
        # scope name -> { key -> state }
        self._state: Dict[str, Dict[tuple, dict]] = {"fast": {}, "slow": {}}
        self._fired: set = set()  # (actor_cluster, resource) already alerted
        # per-actor identity profile for the Web Bot Auth signal
        self._wba_verified: set = set()   # actors that presented valid WBA
        self._claims_agent: set = set()   # actors whose UA claims an agent

    # user-agent substrings that CLAIM to be an automated agent
    _AGENT_UA_RE = re.compile(
        r"(bot|crawler|spider|gpt|claude|agent|python-|httpx|go-http|"
        r"curl|wget|headless|playwright|puppeteer)", re.IGNORECASE)

    def _win(self, scope: str):
        return ((self.window_s, self.max_window_s) if scope == "fast"
                else (self.actor_window_s, self.actor_max_window_s))

    def _armed(self, scope: str, st: dict, ts: float) -> bool:
        idle, cap = self._win(scope)
        return ts - st["last_ts"] <= idle and ts - st["first_ts"] <= cap

    def _find_armed(self, scope: str, actor: str, rk: str, ts: float):
        """Armed state in `scope` for rk OR a parent of it (write-to-child)."""
        store = self._state[scope]
        k = (actor, rk)
        st = store.get(k)
        if st and self._armed(scope, st, ts):
            return k, st
        parts = rk.split("/")
        for i in range(len(parts) - 1, 0, -1):
            pk = (actor, "/".join(parts[:i]))
            pst = store.get(pk)
            if pst and self._armed(scope, pst, ts):
                return pk, pst
        return None, None

    def _arm(self, scope: str, actor: str, rk: str, idx: int, e: Event):
        store = self._state[scope]
        # route-discovery: if an armed ANCESTOR resource already exists for this
        # actor (e.g. denied on 'reports', now probing 'reports/export'),
        # accumulate into that ancestor rather than opening a sibling bucket.
        # This is the Medicare pattern: blocked, then hunt sibling endpoints.
        k, st = self._find_armed(scope, actor, rk, e.ts)
        if st is None:
            k = (actor, rk)
            st = store.get(k)
        if st and self._armed(scope, st, e.ts):
            st["variants"].add(e.path.lower())
            st["attempts"] += 1
            st["last_ts"] = e.ts
            st["attempt_idxs"].append(idx)
            st["ts_list"].append(e.ts)
            cls = _classify_mutation(st["orig_path"], st["orig_method"],
                                     e.path, e.method)
            if cls not in ("same",):
                st["grammar"].append(cls)
        else:
            store[k] = {"first_ts": e.ts, "last_ts": e.ts,
                        "variants": {e.path.lower()}, "attempts": 1,
                        "attempt_idxs": [idx], "ts_list": [e.ts],
                        "orig_path": e.path, "orig_method": e.method,
                        "grammar": []}

    def _enough(self, scope: str, st: dict) -> bool:
        """Scope-aware firing threshold.

        FAST (single session): volume OR variety both count -- a lone session
        repeating a path many times, or rotating encodings, is suspicious
        either way. NAT aggregation can't happen inside one session.

        SLOW (actor cluster / NAT): volume is MEANINGLESS -- many users behind
        one /24 inflate the attempt count without any attack. So require real
        evasion: >= min_alternates distinct variants AND at least one HARD
        evasion grammar class (encoding/dotseg/case/method/version). Benign
        NAT noise (trailing slash, tracking query) never clears this.
        """
        variants = len(st["variants"])
        if scope == "fast":
            return (variants >= self.min_alternates or
                    st["attempts"] >= self.min_attempts)
        hard = len(set(st["grammar"]) & HARD_EVASION)
        return variants >= self.min_alternates and hard >= 1

    def _try_breakthrough(self, scope: str, actor: str, rk: str, idx: int,
                          e: Event):
        """Return (armed_resource, state) if this event completes a sequence in
        `scope`, else (None, None). Mutates the matched state."""
        k, st = self._find_armed(scope, actor, rk, e.ts)
        if not st:
            return None, None
        st["variants"].add(e.path.lower())
        st["attempts"] += 1
        st["last_ts"] = e.ts
        st["attempt_idxs"].append(idx)
        st["ts_list"].append(e.ts)
        cls = _classify_mutation(st["orig_path"], st["orig_method"],
                                 e.path, e.method)
        if cls not in ("same",):
            st["grammar"].append(cls)
        is_write = e.method in ("PUT", "POST", "DELETE", "PATCH")
        breakthrough = e.ok or is_write
        if breakthrough and self._enough(scope, st):
            return k[1], st
        return None, None

    def feed(self, idx: int, e: Event) -> Optional[Detection]:
        if e.direction != "inbound":
            return None
        rk = _resource_key(e.path)
        actor = _actor_cluster(e)

        # update the actor's identity profile (Web Bot Auth signal)
        if e.web_bot_auth:
            self._wba_verified.add(actor)
        if e.user_agent and self._AGENT_UA_RE.search(e.user_agent):
            self._claims_agent.add(actor)

        if e.denied:
            # arm BOTH scopes: session-local and actor-cluster
            self._arm("fast", e.session_id, rk, idx, e)
            self._arm("slow", actor, rk, idx, e)
            return None

        # try to complete a sequence in either scope (fast first; it carries
        # the tighter evidence). Dedupe on (actor, resource).
        for scope, who in (("fast", e.session_id), ("slow", actor)):
            armed_rk, st = self._try_breakthrough(scope, who, rk, idx, e)
            if not st:
                continue
            dedupe = (actor, armed_rk)
            if dedupe in self._fired:
                return None
            # Web Bot Auth: a cryptographically-verified agent acting for a
            # real user is legitimate -- suppress. (Verified upstream; if the
            # flag is set we trust it.)
            if actor in self._wba_verified:
                self._fired.add(dedupe)   # mark so we don't re-evaluate
                return None
            self._fired.add(dedupe)
            nv, na = len(st["variants"]), st["attempts"]
            is_write = e.method in ("PUT", "POST", "DELETE", "PATCH")
            how = "write" if is_write else f"{e.status} success"
            span = e.ts - st["first_ts"]
            scope_note = "" if scope == "fast" else " [cross-session]"
            atype = _classify_timing(st["ts_list"])
            type_note = f" [actor: {atype}]" if atype else ""
            # evasion-grammar signature: ordered, de-duplicated-consecutive
            grammar = st["grammar"]
            sig_parts, prev = [], None
            for g in grammar:
                if g != prev:
                    sig_parts.append(g)
                prev = g
            signature = ",".join(sig_parts)
            sig_note = f" [grammar: {signature}]" if signature else ""
            # upgrade: claims to be an agent but presented NO Web Bot Auth
            # signature -> spoofed/unverified automation. Highest concern.
            severity = "high"
            wba_note = ""
            if actor in self._claims_agent and actor not in self._wba_verified:
                severity = "critical"
                wba_note = " [unverified agent: no Web Bot Auth signature]"
            return Detection(
                detector=self.name, ts=e.ts, session_id=e.session_id,
                src_ip=e.src_ip,
                reason=(f"denied on '{armed_rk}' then {na} attempts "
                        f"({nv} distinct variants) over {span:.1f}s "
                        f"culminating in {how} ({e.method} {e.path})"
                        f"{scope_note}{type_note}{sig_note}{wba_note}"),
                severity=severity,
                evidence_idx=st["attempt_idxs"][:],
                actor_type=atype,
                signature=signature,
            )
        return None


class InjectionTripwireDetector:
    name = "injection_tripwire"

    # LLM scratchpad / instruction artifacts that shouldn't appear in traffic
    _ARTIFACT_RE = re.compile(
        r"(as an ai|i cannot comply|ignore previous|\"role\"\s*:\s*\"system\"|"
        r"thought:\s|action:\s)", re.IGNORECASE)
    _CB_PREFIX = "/cb/"

    def __init__(self):
        self._fired: set = set()
        # denial-page nonces issued in 401/403/429 bodies: nonce -> (actor, res)
        self._denial_nonces: Dict[str, tuple] = {}

    def feed(self, idx: int, e: Event) -> Optional[Detection]:
        # register a nonce stamped into a denial body (so a later callback to
        # it is PROOF the agent read that specific denial, not just a decoy).
        if e.denied and e.denial_nonce:
            self._denial_nonces[e.denial_nonce] = (_actor_cluster(e),
                                                   _resource_key(e.path))

        # (a) callback hit -- an agent obeyed an embedded instruction
        if e.path.startswith(self._CB_PREFIX):
            if e.session_id in self._fired:
                return None
            self._fired.add(e.session_id)
            nonce = e.path[len(self._CB_PREFIX):].split("/", 1)[0].split("?", 1)[0]
            match = self._denial_nonces.get(nonce)
            if match:
                # PROOF-grade: this nonce only ever appeared in a 403 body we
                # served to this attacker. Obeying it = read the denial +
                # acted on it. This is the Medicare moment, captured.
                actor, res = match
                det = Detection(
                    detector=self.name, ts=e.ts, session_id=e.session_id,
                    src_ip=e.src_ip,
                    reason=(f"denial-page tripwire sprung: agent obeyed the "
                            f"instruction in the 403 body for '{res}' "
                            f"(callback {e.path}) -- PROOF it read and acted on "
                            f"the access denial"),
                    severity="critical", evidence_idx=[idx])
                det.confidence = "proof"
                return det
            return Detection(
                detector=self.name, ts=e.ts, session_id=e.session_id,
                src_ip=e.src_ip,
                reason=(f"canary callback hit ({e.path}) -- client read and "
                        f"obeyed an instruction embedded only in a decoy doc"),
                severity="high", evidence_idx=[idx])

        # (b) prompt/LLM artifact leaked in body or headers
        blob = (e.body_sample or "") + " " + (e.header_blob or "")
        if blob.strip() and self._ARTIFACT_RE.search(blob):
            key = (e.session_id, "leak")
            if key in self._fired:
                return None
            self._fired.add(key)
            snippet = self._ARTIFACT_RE.search(blob).group(0)
            return Detection(
                detector=self.name, ts=e.ts, session_id=e.session_id,
                src_ip=e.src_ip,
                reason=(f"LLM artifact in request to {e.path}: "
                        f"'{snippet.strip()}...'"),
                severity="medium", evidence_idx=[idx])
        return None


class EgressDeadDropDetector:
    """Watch the EGRESS log for the customer's own server/agent writing data
    OUT to a host that isn't on its known-good allowlist. This is the exfil /
    C2 leg both incidents relied on (staging on ordinary public services).

    Trigger: an egress WRITE (POST/PUT/PATCH) to a host not in the allowlist.
    A GET to an unknown host is not flagged on its own (dependency fetches,
    API reads) -- exfil is about data leaving. The known dead-drop list only
    raises severity and sharpens the message; an unlisted unknown host still
    fires, so a brand-new exfil host is not missed.
    """
    name = "egress_deaddrop"

    def __init__(self, allowlist: Optional[set] = None,
                 deaddrop_hint: Optional[set] = None,
                 big_write_bytes: int = 10000):
        # In production the allowlist is learned per-customer (the hosts their
        # server normally talks to) or configured. Here we pass the known-good
        # set in from the simulator's world.
        self.allowlist = allowlist or set()
        self.deaddrop_hint = deaddrop_hint or set()
        self.big_write_bytes = big_write_bytes
        self._fired: set = set()

    def feed(self, idx: int, e: Event) -> Optional[Detection]:
        if e.direction != "egress":
            return None
        if e.method not in ("POST", "PUT", "PATCH"):
            return None
        host = e.dest_host.lower()
        if host in self.allowlist:
            return None
        key = (e.session_id, host)
        if key in self._fired:
            return None
        self._fired.add(key)
        known_bad = host in self.deaddrop_hint
        big = e.bytes_out >= self.big_write_bytes
        severity = "high" if (known_bad or big) else "medium"
        tag = "known dead-drop host" if known_bad else "unlisted external host"
        return Detection(
            detector=self.name, ts=e.ts, session_id=e.session_id,
            src_ip=e.src_ip,
            reason=(f"server wrote {e.bytes_out}B out to {tag} '{host}' "
                    f"({e.method}) -- possible exfil/C2"),
            severity=severity, evidence_idx=[idx])


class KillChainDetector:
    """Correlate an actor's activity into a single attack-campaign alert.

    The individual detectors each see one leg. This one models the whole web
    kill chain the two incidents walked and fires once the actor has traversed
    enough of it -- the line you put at the TOP of the incident report.

    Stages (ordered):
        1 recon        -- enumeration misses (404/410) across paths
        2 deny         -- hit an access control (401/403/429/paywall)
        3 evade        -- another attempt at a denied resource (variant)
        4 breakthrough -- a 2xx on a previously-denied resource
        5 write        -- a write method (PUT/POST/PATCH/DELETE) after a deny
        6 egress       -- data written OUT to a non-allowlisted host
    Plus a confirming signal (not a stage number):
        callback       -- obeyed a canary/denial instruction (proof of agent)

    Fires HIGH when the actor reaches >=`min_stages` distinct stages, OR makes
    a stage JUMP of >=2 (e.g. deny -> write with no normal access between),
    which ChainWatch uses as its strongest rule. Dedup per actor.
    """
    name = "kill_chain"

    def __init__(self, allowlist: Optional[set] = None, min_stages: int = 3,
                 window_s: float = 86400.0):
        self.allowlist = allowlist or set()
        self.min_stages = min_stages
        self.window_s = window_s
        self._st: Dict[str, dict] = {}   # actor -> {stages:set, last_stage, ...}
        self._fired: set = set()
        # per-actor: resources we've seen denied, to recognise a later 2xx as a
        # breakthrough stage rather than normal traffic.
        self._denied_res: Dict[str, set] = defaultdict(set)
        # exact denied paths per actor, and actors that have shown an evasion
        # VARIANT (different path to a denied resource). Breakthrough/write
        # stages only count once evasion is seen -- so a legit 401->refresh->
        # 200 on the SAME path is not mistaken for block defiance.
        self._denied_paths: Dict[str, set] = defaultdict(set)
        self._evaded: set = set()

    def _stage_for(self, e: Event, actor: str) -> Optional[int]:
        rk = _resource_key(e.path)
        if e.direction == "egress":
            if e.method in ("POST", "PUT", "PATCH") and \
               e.dest_host.lower() not in self.allowlist:
                return 6
            return None
        if e.path.startswith("/cb/"):
            return None  # handled as callback confirm, not a stage
        if e.notfound:
            return 1
        if e.denied:
            self._denied_res[actor].add(rk)
            self._denied_paths[actor].add(e.path)
            return 2
        # a request to a resource previously denied for this actor:
        prev_denied = any(rk == d or rk.startswith(d + "/") or d.startswith(rk + "/")
                          for d in self._denied_res[actor])
        if prev_denied:
            is_write = e.method in ("PUT", "POST", "DELETE", "PATCH")
            # A plain retry of the SAME path after a deny is NOT evasion -- it's
            # usually a legit re-request after an auth/token step (SPA refresh).
            # Only count breakthrough/write/evade once the actor has shown an
            # EVASION variant: a DIFFERENT path/encoding against the denied
            # resource. We track that per actor as 'evaded'.
            orig = self._denied_paths[actor]
            is_variant = e.path not in orig  # a path we didn't see denied
            if is_variant:
                self._evaded.add(actor)
            if actor not in self._evaded:
                # no evasion seen yet: a same-path 200/ write is normal auth flow
                self._denied_paths[actor].add(e.path)
                return None
            if is_write:
                return 5
            if e.ok:
                return 4
            return 3  # another non-success attempt = evade
        return None  # normal traffic to a never-denied resource

    def feed(self, idx: int, e: Event) -> Optional[Detection]:
        actor = _actor_cluster(e)
        callback = e.path.startswith("/cb/") and e.direction == "inbound"
        stage = self._stage_for(e, actor)
        if stage is None and not callback:
            return None

        st = self._st.get(actor)
        if not st or e.ts - st["last_ts"] > self.window_s:
            st = {"stages": set(), "last_stage": 0, "first_ts": e.ts,
                  "last_ts": e.ts, "idxs": [], "callback": False,
                  "max_jump": 0, "last_sid": e.session_id}
            self._st[actor] = st

        st["last_ts"] = e.ts
        st["idxs"].append(idx)
        if callback:
            st["callback"] = True
        if stage is not None:
            if st["last_stage"] and stage - st["last_stage"] >= 2:
                st["max_jump"] = max(st["max_jump"], stage - st["last_stage"])
            st["stages"].add(stage)
            st["last_stage"] = stage

        reached = len(st["stages"])
        jump = st["max_jump"] >= 2
        if (reached >= self.min_stages or jump) and actor not in self._fired:
            self._fired.add(actor)
            names = {1: "recon", 2: "deny", 3: "evade", 4: "breakthrough",
                     5: "write", 6: "egress"}
            chain = " -> ".join(names[s] for s in sorted(st["stages"]))
            if st["callback"]:
                chain += " (+canary callback: confirmed agent)"
            why = (f"jump of {st['max_jump']} stages" if jump
                   else f"{reached} kill-chain stages")
            return Detection(
                detector=self.name, ts=e.ts, session_id=e.session_id,
                src_ip=e.src_ip,
                reason=(f"multi-stage campaign from {actor}: {chain} [{why}]"),
                severity="high", evidence_idx=st["idxs"][:])
        return None


def run_detectors(events: Iterable[Event],
                  detectors: Optional[list] = None) -> List[Detection]:
    if detectors is None:
        # Default egress allowlist/hint pulled from the sim world for the PoC;
        # in production these are per-customer config/learned.
        try:
            from simulator import KNOWN_GOOD_HOSTS, DEADDROP_HOSTS
            allow, hint = set(KNOWN_GOOD_HOSTS), set(DEADDROP_HOSTS)
        except Exception:
            allow, hint = set(), set()
        detectors = [BlockDefianceDetector(), InjectionTripwireDetector(),
                     EgressDeadDropDetector(allowlist=allow, deaddrop_hint=hint),
                     KillChainDetector(allowlist=allow)]
    out: List[Detection] = []
    for idx, e in enumerate(events):
        for d in detectors:
            det = d.feed(idx, e)
            if det:
                out.append(det)
    return out
