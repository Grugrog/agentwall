"""
Shared data model for the AgentWall PoC.

An HTTP request/response pair observed at the edge (reverse proxy / WAF /
app middleware) is reduced to the fields a detector actually needs. This is
deliberately the kind of record you can reconstruct from an nginx/Cloudflare
log line plus a little request-body sampling -- nothing exotic.

Nothing in here touches a real network. The simulator fabricates these
records; detectors only ever read them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Response "class" from the client's point of view. A detector cares whether
# the server said no, not the exact code, so we collapse to a few buckets but
# keep the raw status for reporting.
DENY_STATUSES = {401, 403, 429}          # explicit refusal
PAYWALL_STATUSES = {402, 451}            # blocked-for-policy
NOTFOUND_STATUSES = {404, 410}           # probing / enumeration
OK_STATUSES = {200, 201, 204, 206, 301, 302}  # got something useful


@dataclass
class Event:
    # identity / correlation
    ts: float                      # unix-ish seconds (monotonic in sim)
    session_id: str                # proxy session / connection id
    src_ip: str
    user_agent: str

    # the request
    method: str
    path: str
    status: int
    bytes_out: int = 0

    # direction of the observation.
    #   "inbound" -> a client hitting the customer's site (reverse-proxy log)
    #   "egress"  -> the customer's own server/agent reaching OUT (firewall /
    #                egress-proxy log). dest_host is the external host it hit.
    # Both incidents staged exfil/C2 on ordinary public hosts, so egress is a
    # separate, high-value log source.
    direction: str = "inbound"
    dest_host: str = ""            # set for egress events

    # denial-page tripwire: when the server returns a 401/403/429 it stamps a
    # one-time nonce into the response body ("agents: use GET /cb/<nonce>").
    # On the DENY event this holds the issued nonce; a later /cb/<nonce> hit
    # that matches proves an agent read+obeyed the denial body.
    denial_nonce: str = ""

    # optional signals a real edge can cheaply capture
    body_sample: str = ""          # first N bytes of request body, sampled
    header_blob: str = ""          # concatenated non-standard headers
    has_referer: bool = True
    web_bot_auth: bool = False     # presented a valid Web Bot Auth signature

    # ground truth -- ONLY the simulator sets this. Detectors must never read
    # it. The eval harness uses it to score. Values: "human", "goodbot",
    # "attacker".
    truth: str = field(default="human")

    # --- convenience predicates -------------------------------------------
    @property
    def denied(self) -> bool:
        return self.status in DENY_STATUSES or self.status in PAYWALL_STATUSES

    @property
    def notfound(self) -> bool:
        return self.status in NOTFOUND_STATUSES

    @property
    def ok(self) -> bool:
        return self.status in OK_STATUSES


@dataclass
class Detection:
    """A detector firing. Scored against Event.truth by the harness."""
    detector: str                  # which detector fired
    ts: float                      # when it fired (of the triggering event)
    session_id: str
    src_ip: str
    reason: str                    # human-readable why
    severity: str = "high"         # low | medium | high | critical
    # the event indices (into the stream) that make up the evidence
    evidence_idx: list = field(default_factory=list)
    # optional enrichment fields set by specific detectors
    actor_type: str = ""           # script | agent | human-like | "" (timing)
    signature: str = ""            # evasion-grammar signature (ordered classes)
    confidence: str = ""           # behavioural | proof (denial-page callback)
