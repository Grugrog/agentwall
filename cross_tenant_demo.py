"""
Prove the moat: catch a distributed swarm that NO single tenant's local
detector would fire on, and DON'T false-correlate unrelated benign noise.
"""
from events import Event
from detectors import run_detectors
from correlation import CrossTenantCorrelator, extract_signals

def quiet_probe(tenant_net_prefix, resource, variants, t0):
    """One tenant sees a short, sub-threshold grind: a deny + <threshold
    evasion variants, NO breakthrough. Local detector must stay silent."""
    ev = []; t = t0
    ip = tenant_net_prefix + ".9"
    ev.append(Event(ts=t, session_id="s", src_ip=ip, user_agent="python-requests/2.32",
                    method="GET", path=resource, status=403, truth="attacker")); t += 30
    for v in variants:
        ev.append(Event(ts=t, session_id="s", src_ip=ip, user_agent="python-requests/2.32",
                        method="GET", path=v, status=403, truth="attacker")); t += 30
    return ev

print("=== Distributed swarm: same grammar, 5 tenants, each sub-threshold ===")
# Same agent/tool -> same evasion grammar (encoding+dotseg) at every victim.
# Each tenant sees only deny + 2 variants, no breakthrough -> local = silent.
tenants = {
    "conveyancer-A": ("203.0.11", "/portal", ["/portal%2e", "/../portal"]),
    "conveyancer-B": ("198.51.1", "/client-area", ["/client-area%2e", "/../client-area"]),
    "gp-clinic-C":   ("192.0.2",  "/portal", ["/portal%2e", "/../portal"]),
    "law-firm-D":    ("203.0.12", "/admin", ["/admin%2e", "/../admin"]),
    "conveyancer-E": ("198.51.2", "/portal", ["/portal%2e", "/../portal"]),
}
local_fires = 0
all_sigs = []
t0 = 1000.0
for i,(name,(net,res,vars)) in enumerate(tenants.items()):
    ev = quiet_probe(net, res, vars, t0 + i*3600)  # spread over hours
    # local detector on this tenant alone:
    if [d for d in run_detectors(ev) if d.detector in ("block_defiance","kill_chain")]:
        local_fires += 1
    all_sigs += extract_signals(ev, name)

print(f"local detector fired at: {local_fires} / {len(tenants)} tenants (expected 0 -- all sub-threshold)")
corr = CrossTenantCorrelator(min_tenants=3)
alerts = corr.ingest_many(all_sigs)
print(f"correlator swarm alerts: {len(alerts)} (expected >=1)")
for a in alerts:
    print("  ->", a.reason)
    print("     tenants:", a.tenants)

print("\n=== Negative control: unrelated benign-ish noise, different grammars ===")
# Each tenant has a DIFFERENT, benign-looking single-variant quirk. Must NOT correlate.
noise = []
for i,(name,net,res,var) in enumerate([
    ("shop-F","203.0.20","/cart","/cart/"),      # trailing slash
    ("blog-G","198.51.3","/post","/post?utm=x"), # tracking query
    ("news-H","192.0.9","/feed","/feed/"),        # trailing slash
    ("wiki-I","203.0.21","/page","/page#top"),    # fragment
]):
    ev=[Event(ts=1000.0+i*3600,session_id="s",src_ip=net+".9",user_agent="Mozilla/5.0 Chrome/141",
              method="GET",path=res,status=403,truth="human"),
        Event(ts=1001.0+i*3600,session_id="s",src_ip=net+".9",user_agent="Mozilla/5.0 Chrome/141",
              method="GET",path=var,status=403,truth="human")]
    noise += extract_signals(ev, name)
corr2 = CrossTenantCorrelator(min_tenants=3)
alerts2 = corr2.ingest_many(noise)
print(f"signals emitted: {len(noise)}  swarm alerts: {len(alerts2)} (expected 0 -- different grammars, no hard evasion)")
for a in alerts2:
    print("  FALSE ->", a.reason)

print("\n=== Mixed: swarm hidden inside benign noise ===")
corr3 = CrossTenantCorrelator(min_tenants=3)
mixed = all_sigs + noise
a3 = corr3.ingest_many(mixed)
print(f"swarm alerts from mixed stream: {len(a3)} "
      f"(expected 2 tiers of the SAME real swarm, 0 from the noise)")
for a in a3:
    print("  ->", a.signature, "@", a.shape, "across", len(a.tenants), "tenants")
