# Deploying the AgentWall honeypot for real collection

The honeypot only sees traffic that reaches it. To collect real agent/scanner
activity you must run it on infrastructure you own, on a plausible hostname.

## Safety and legal (read first)
- **Passive only.** The honeypot never contacts a client back, never touches
  the caller's systems, serves only inert decoys, and holds no real data. Keep
  it that way. Do not add any "load army" / counter-fetch behaviour — reaching
  into someone else's agent or host engages Criminal Code Part 10.7.
- Run it on **your own** hosts/domains. Don't impersonate a real org.
- Decoy content is clearly fake (`TEST-ONLY-DECOY`). Don't seed real secrets.

## Minimal deploy (single VPS)
1. Put the honeypot behind a reverse proxy that terminates TLS and, crucially,
   passes the **real client IP** through (the detectors cluster on it):

   nginx:
   ```
   location / {
     proxy_pass http://127.0.0.1:8899;
     proxy_set_header X-Forwarded-For $remote_addr;
     proxy_set_header Host $host;
   }
   ```
   Then run the honeypot with a small patch to read `X-Forwarded-For` as
   `src_ip` (the handler already reads headers; wire it in for production).

2. systemd unit:
   ```
   [Unit]
   Description=AgentWall honeypot
   After=network.target
   [Service]
   ExecStart=/usr/bin/python3 /opt/agentwall/honeypot.py --host 127.0.0.1 --port 8899 --log /var/log/agentwall/hp.jsonl
   Restart=always
   [Install]
   WantedBy=multi-user.target
   ```

3. Make it findable (that's the point): a real subdomain
   (`portal.<yourdomain>`), linked from nowhere sensitive, listed in
   `robots.txt`/`llms.txt` as the server already advertises. Agents and
   scanners crawl these.

4. Analyse on a schedule:
   ```
   */10 * * * * python3 /opt/agentwall/analyze.py /var/log/agentwall/hp.jsonl >> /var/log/agentwall/report.txt
   ```

## Behind Cloudflare (recommended)
- Proxy the subdomain through Cloudflare. Enable **Logpush** (free on all
  plans since 30 Sep 2026) to ship request logs, and run `ingest.py --format
  cloudflare` on them in addition to the origin honeypot log. Cloudflare's own
  bot score / Web Bot Auth verdicts become extra columns you can fuse.

## Running it on a phone / behind CGNAT (S26 Termux or Linux Terminal)
The server runs anywhere Python 3 does, but a phone (or any host behind
carrier CGNAT / home NAT) gets **no inbound internet**, so it won't see real
traffic without a public ingress. Use a tunnel:

```
# on the phone: run the honeypot bound to loopback, trusting the tunnel's XFF
python3 honeypot.py --host 127.0.0.1 --port 8899 --trust-proxy &
# expose it with a Cloudflare Tunnel (free; gives a public hostname + TLS)
cloudflared tunnel --url http://127.0.0.1:8899
```
Termux: `pkg install python`, and `termux-wake-lock` or Android kills it.
S26 Linux Terminal (Debian VM): `apt install python3`; systemd may work for
the unit file, else run under `tmux`. Good for dev/testing; for always-on
collection a $5 VPS is steadier than a phone.

## What to expect honestly
- Real autonomous-agent hits are still **rare**. Expect mostly commodity
  scanners and crawlers at first. Palisade's SSH honeypot saw ~a handful of
  confirmed AI agents in 11M+ attempts. Treat early data as a feed for tuning
  false positives on real traffic, not as proof of demand.
- The value of the first weeks is a real false-positive baseline on your own
  benign traffic — the number a security buyer actually asks for.

## For a production deployment on customer sites
The honeypot is the *advertising/collection* arm. The detector pipeline
(`ingest.py` + `detectors.py`) runs on the **customer's real logs** (nginx /
Cloudflare Logpush), not only the honeypot. That's where block_defiance earns
its keep — on the customer's actual portal, not a decoy.
