# Setup / sync

Python 3 stdlib only — no `pip install`. Clone and run:
```
python3 eval.py        # confirm baseline: 98.2% / 100% / 0 FP
```

## Push to GitHub (account: Grugrog)
From your machine, logged in as yourself (`gh auth login`):
```
cd agentwall
git init && git add -A && git commit -m "AgentWall"
gh repo create Grugrog/agentwall --private --source=. --push
```
Or with an existing empty repo:
```
git remote add origin https://github.com/Grugrog/agentwall.git
git branch -M main && git push -u origin main
```

## Run the honeypot for real collection
See `DEPLOY.md`. Short version — on a VPS or behind a Cloudflare Tunnel:
```
python3 honeypot.py --host 127.0.0.1 --port 8899 --trust-proxy
cloudflared tunnel --url http://127.0.0.1:8899     # free public ingress + TLS
```
The `claude` CLI does NOT run in Termux (Android libc) — use a glibc Linux
(the Debian "Linux Terminal", a VPS) for that; Termux is fine for the honeypot.

## Patches
`patches/agentwall-fp-fix.patch` and `patches/events-fields-fix.patch` are
**already applied** in this tree. They are kept for the record / for applying to
an older checkout:
```
git apply patches/events-fields-fix.patch
git apply patches/agentwall-fp-fix.patch
```
