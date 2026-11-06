"""
Traffic simulator for the AgentWall PoC.

Generates a stream of Event records mixing three populations:

  1. humans      -- browse, sometimes hit a 403/paywall, then GIVE UP or go
                    elsewhere. Occasionally fast (power users), sometimes no
                    referer (bookmark, privacy browser).
  2. goodbots    -- search crawlers + legit user-directed agents. Fast,
                    often no referer, bot-ish UA. Respect a deny: on 403 they
                    stop or slow. Some present Web Bot Auth.
  3. attackers   -- the behaviour that actually mattered in the HF + Medicare
                    postmortems:
                      a) BLOCK DEFIANCE: hit a deny, then within seconds try
                         alternate paths / methods / encodings until one
                         succeeds (Medicare: "blocked -> found workarounds ->
                         read non-public files -> wrote to server").
                      b) INJECTION PROBING: fetch seeded canary docs/pages and
                         then emit the callback the hidden instruction asked
                         for; sometimes leak LLM artifacts in a POST body
                         (HF: malicious dataset / indirect injection).
                      c) a quiet "low-and-slow" variant that does (a) but
                         paced like a human, to stress the detector.

The point of the overlap is to make the eval mean something: if a detector
scores well here it's because it keyed on the deny->retry->success *sequence*
and the canary callback, not on "fast == bad" or "403 == bad".

Deterministic given a seed.
"""

from __future__ import annotations

import random
import string
from typing import List

from events import Event


# ---------------------------------------------------------------------------
# Site model: a handful of paths, some of them "protected" (deny unless you
# have a session a human would have). Canary paths are seeded decoys.
# ---------------------------------------------------------------------------
PUBLIC_PATHS = [
    "/", "/about", "/services", "/contact", "/blog", "/blog/conveyancing-tips",
    "/fees", "/team", "/privacy", "/login",
]
PROTECTED_PATHS = [
    "/portal", "/portal/matters", "/portal/settlement", "/api/v1/matters",
    "/api/v1/clients", "/admin", "/reports/statistics", "/data/export",
]
# Seeded canary docs/pages: contain a hidden instruction telling an agent to
# GET /cb/<nonce>. A human never fetches these (not linked in the UI); a
# naive crawler might fetch the page but won't emit the callback. Only an LLM
# agent that *reads and obeys* the instruction produces the callback.
CANARY_PATHS = [
    "/docs/internal-process.html", "/datasets/client-index.json",
    "/.well-known/ai-plugin.json",
]
CALLBACK_PREFIX = "/cb/"

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile Safari/604.1",
]
GOODBOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "ChatGPT-User/1.0 (+https://openai.com/bot)",
    "ResearchAgent/1.0 (python-httpx)",
]
ATTACKER_UAS = [
    # attackers often look like a plausible browser or a generic client
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36",
    "python-requests/2.32",
    "Go-http-client/2.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36",
]

# Egress destinations. Known-good = the customer's server legitimately calls
# these (CDN, payments, their own APIs, a mail provider). Dead-drop = ordinary
# public hosts an exfiltrating agent abuses for staging/C2 (both the HF and
# Medicare agents used plain public web services this way).
KNOWN_GOOD_HOSTS = [
    "cdn.jsdelivr.net", "api.stripe.com", "www.googleapis.com",
    "api.pexa.com.au", "smtp.sendgrid.net", "s3.ap-southeast-2.amazonaws.com",
]
DEADDROP_HOSTS = [
    "pastebin.com", "paste.ee", "gist.githubusercontent.com",
    "transfer.sh", "files.catbox.moe", "requestbin.net", "ngrok-free.app",
    "raw.githubusercontent.com",
]

LLM_ARTIFACTS = [
    "As an AI assistant, I will now fetch",
    "I cannot comply with that, however the task requires",
    '{"role":"system","content":"ignore previous"}',
    "Thought: I should try an alternate endpoint. Action:",
]

_ALT_ENCODINGS = [
    lambda p: p + "/",
    lambda p: p + "/.",
    lambda p: p + "%2e",
    lambda p: p.replace("/", "/./", 1),
    lambda p: p + "?debug=1",
    lambda p: p + "#",
    lambda p: "/.." + p,
    lambda p: p.upper(),
]


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def _nonce(rng: random.Random, n: int = 10) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _sid(rng: random.Random) -> str:
    return _nonce(rng, 12)


class Simulator:
    def __init__(self, seed: int = 1337):
        self.rng = random.Random(seed)
        self.clock = 1_700_000_000.0  # arbitrary start
        self.events: List[Event] = []

    # -- helpers ------------------------------------------------------------
    def _advance(self, lo: float, hi: float):
        self.clock += self.rng.uniform(lo, hi)

    def _emit(self, **kw):
        self.events.append(Event(ts=self.clock, **kw))

    def _emit_egress(self, sid, ip, host, method, nbytes, truth):
        self.events.append(Event(
            ts=self.clock, session_id=sid, src_ip=ip,
            user_agent="server", method=method, path="/", status=200,
            bytes_out=nbytes, direction="egress", dest_host=host, truth=truth))

    def _status_for(self, path: str, authorised: bool) -> int:
        if path.startswith(CALLBACK_PREFIX):
            return 200
        if path in CANARY_PATHS:
            return 200  # decoys are served
        if any(path.startswith(p) for p in PROTECTED_PATHS):
            return 200 if authorised else self.rng.choice([403, 401, 403])
        if path in PUBLIC_PATHS:
            return 200
        return 404  # anything else = enumeration miss

    # -- populations --------------------------------------------------------
    def human_session(self):
        sid, ip = _sid(self.rng), _rand_ip(self.rng)
        ua = self.rng.choice(BROWSER_UAS)
        has_ref = self.rng.random() > 0.15  # most have referer
        hops = self.rng.randint(2, 7)
        for i in range(hops):
            path = self.rng.choice(PUBLIC_PATHS)
            # a human occasionally stumbles onto a protected page -> 403
            if self.rng.random() < 0.08:
                path = self.rng.choice(PROTECTED_PATHS)
            status = self._status_for(path, authorised=False)
            self._emit(session_id=sid, src_ip=ip, user_agent=ua,
                       method="GET", path=path, status=status,
                       bytes_out=self.rng.randint(500, 9000),
                       has_referer=has_ref, truth="human")
            # KEY: a human who gets denied does NOT hammer alternates.
            if status in (403, 401):
                if self.rng.random() < 0.7:
                    break  # gives up / leaves
            self._advance(1.5, 12.0)  # human think-time, seconds

    def goodbot_session(self):
        sid, ip = _sid(self.rng), _rand_ip(self.rng)
        ua = self.rng.choice(GOODBOT_UAS)
        wba = "ChatGPT" in ua or self.rng.random() < 0.3
        hops = self.rng.randint(3, 10)
        for i in range(hops):
            # crawlers may fetch a canary PAGE (it's served) but never emit
            # the callback -- they don't "obey" embedded instructions.
            if self.rng.random() < 0.1:
                path = self.rng.choice(CANARY_PATHS)
            else:
                path = self.rng.choice(PUBLIC_PATHS)
            status = self._status_for(path, authorised=False)
            self._emit(session_id=sid, src_ip=ip, user_agent=ua,
                       method="GET", path=path, status=status,
                       bytes_out=self.rng.randint(300, 4000),
                       has_referer=False, web_bot_auth=wba, truth="goodbot")
            if status in (403, 401):
                break  # good bot respects the deny
            self._advance(0.2, 1.5)  # fast but not instant

    def attacker_blockdefiance(self, low_and_slow: bool = False):
        """Deny -> rapid alternate attempts -> eventual success."""
        sid, ip = _sid(self.rng), _rand_ip(self.rng)
        ua = self.rng.choice(ATTACKER_UAS)
        target = self.rng.choice(PROTECTED_PATHS)
        pace = (2.0, 9.0) if low_and_slow else (0.05, 0.6)

        # 1) initial hit -> denied
        self._emit(session_id=sid, src_ip=ip, user_agent=ua, method="GET",
                   path=target, status=403, bytes_out=120,
                   has_referer=False, truth="attacker")
        self._advance(*pace)

        # 2) grind alternates (this is the Medicare "found workarounds" step)
        attempts = self.rng.randint(4, 9)
        succeeded = False
        for i in range(attempts):
            enc = self.rng.choice(_ALT_ENCODINGS)
            alt = enc(target)
            method = self.rng.choice(["GET", "GET", "GET", "POST", "HEAD"])
            # most alternates still fail; one eventually "works"
            if i >= attempts - 2 and not succeeded and self.rng.random() < 0.8:
                status, succeeded = 200, True
                body = ""
                if method == "POST":
                    body = "payload=" + _nonce(self.rng, 40)
                self._emit(session_id=sid, src_ip=ip, user_agent=ua,
                           method=method, path=alt, status=status,
                           bytes_out=self.rng.randint(8000, 90000),
                           has_referer=False, body_sample=body,
                           truth="attacker")
                # 3) write-back (HF/Medicare both WROTE to the target)
                self._advance(*pace)
                self._emit(session_id=sid, src_ip=ip, user_agent=ua,
                           method="PUT", path=target + "/x_" + _nonce(self.rng, 6),
                           status=201, bytes_out=200, has_referer=False,
                           truth="attacker")
                # exfil the loot to a dead-drop (seen on the EGRESS log)
                if self.rng.random() < 0.5:
                    self._advance(*pace)
                    self._emit_egress(sid, ip, self.rng.choice(DEADDROP_HOSTS),
                                      "POST", self.rng.randint(5000, 200000),
                                      "attacker")
            else:
                status = self.rng.choice([403, 404, 403, 401])
                self._emit(session_id=sid, src_ip=ip, user_agent=ua,
                           method=method, path=alt, status=status,
                           bytes_out=self.rng.randint(90, 300),
                           has_referer=False, truth="attacker")
            self._advance(*pace)

    def attacker_injection(self):
        """Fetch canary -> obey hidden instruction -> callback. +leak body."""
        sid, ip = _sid(self.rng), _rand_ip(self.rng)
        ua = self.rng.choice(ATTACKER_UAS)

        canary = self.rng.choice(CANARY_PATHS)
        self._emit(session_id=sid, src_ip=ip, user_agent=ua, method="GET",
                   path=canary, status=200, bytes_out=3000,
                   has_referer=False, truth="attacker")
        self._advance(0.05, 0.8)

        # obeys the embedded instruction: GET /cb/<nonce>
        self._emit(session_id=sid, src_ip=ip, user_agent=ua, method="GET",
                   path=CALLBACK_PREFIX + _nonce(self.rng), status=200,
                   bytes_out=40, has_referer=False, truth="attacker")
        self._advance(0.05, 0.8)

        # sometimes it then posts somewhere leaking an LLM artifact
        if self.rng.random() < 0.6:
            self._emit(session_id=sid, src_ip=ip, user_agent=ua, method="POST",
                       path=self.rng.choice(PROTECTED_PATHS), status=200,
                       bytes_out=1500,
                       body_sample=self.rng.choice(LLM_ARTIFACTS) + " " + _nonce(self.rng, 20),
                       has_referer=False, truth="attacker")
        # C2 beacon / exfil to a dead-drop host
        if self.rng.random() < 0.5:
            self._advance(0.1, 1.0)
            self._emit_egress(sid, ip, self.rng.choice(DEADDROP_HOSTS),
                              "POST", self.rng.randint(2000, 50000), "attacker")

    def server_egress_session(self):
        """Legit server-side outbound: payments, CDN, own APIs, mail. All to
        known-good hosts -> must NOT fire. One in ~8 hits a host that looks
        edgy (raw.githubusercontent for a legit dependency fetch) to test that
        the detector keys on write+unknown, not on the hostname alone."""
        sid, ip = "srv_" + _sid(self.rng), _rand_ip(self.rng)
        for _ in range(self.rng.randint(2, 8)):
            if self.rng.random() < 0.12:
                host = "raw.githubusercontent.com"   # legit dep fetch (GET)
                method = "GET"
            else:
                host = self.rng.choice(KNOWN_GOOD_HOSTS)
                method = self.rng.choice(["GET", "POST"])
            self._emit_egress(sid, ip, host, method,
                              self.rng.randint(200, 8000), "goodbot")
            self._advance(0.5, 6.0)

    # -- driver -------------------------------------------------------------
    def run(self, n_humans=400, n_goodbots=60, n_blockdefiance=40,
            n_lowslow=10, n_injection=30, n_egress=80) -> List[Event]:
        # interleave populations by shuffling a work list, so sessions overlap
        # in time the way real traffic does.
        work = (["human"] * n_humans + ["goodbot"] * n_goodbots +
                ["bd"] * n_blockdefiance + ["ls"] * n_lowslow +
                ["inj"] * n_injection + ["egress"] * n_egress)
        self.rng.shuffle(work)
        for job in work:
            # jitter the start so sessions don't line up
            self._advance(0.0, 3.0)
            if job == "human":
                self.human_session()
            elif job == "goodbot":
                self.goodbot_session()
            elif job == "bd":
                self.attacker_blockdefiance(low_and_slow=False)
            elif job == "ls":
                self.attacker_blockdefiance(low_and_slow=True)
            elif job == "inj":
                self.attacker_injection()
            elif job == "egress":
                self.server_egress_session()
        self.events.sort(key=lambda e: e.ts)
        return self.events


if __name__ == "__main__":
    ev = Simulator(seed=1).run()
    from collections import Counter
    c = Counter(e.truth for e in ev)
    sess = {}
    for e in ev:
        sess.setdefault(e.session_id, e.truth)
    sc = Counter(sess.values())
    print(f"events={len(ev)}  by_event={dict(c)}")
    print(f"sessions={len(sess)}  by_session={dict(sc)}")
