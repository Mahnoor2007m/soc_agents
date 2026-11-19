"""Tools used by agents. Each tool is a plain function -> easy to test and to wrap as LangChain/CrewAI tools."""
import json, os, statistics, urllib.request
from datetime import datetime
import pandas as pd

D = os.path.join(os.path.dirname(__file__), "data")
FMT = "%Y-%m-%d %H:%M:%S"
_cache = {}
def _csv(n):
    if n not in _cache: _cache[n] = pd.read_csv(os.path.join(D, f"{n}.csv"), keep_default_na=False)
    return _cache[n]
def _json(n):
    if n not in _cache: _cache[n] = json.load(open(os.path.join(D, f"{n}.json")))
    return _cache[n]

def load_alerts(): return _csv("alerts").to_dict("records")
def allowlist(): return _json("allowlist")
def asset_info(host=None, ip=None):
    a = _csv("assets")
    r = a[(a.host == host) | (a.ip == ip)] if (host or ip) else a.iloc[0:0]
    return r.iloc[0].to_dict() if len(r) else {"host": host, "criticality": "unknown", "owner": "unknown"}
def owner_of(host):
    a = _csv("assets"); r = a[a.host == host]
    return r.iloc[0].owner if len(r) and r.iloc[0].owner != "-" else ""

# ---------- Log tools ----------
def query_auth_logs(user=None, ip=None, host=None, start=None, end=None):
    df = _csv("auth_logs")
    m = pd.Series(False, index=df.index)
    if user: m |= df.user == user
    if ip:   m |= df.src_ip == ip
    if host: m |= df.host == host
    df = df[m]
    if start: df = df[df.time >= start]
    if end:   df = df[df.time <= end]
    return df.to_dict("records")

def query_network_logs(src_ip=None, dst_ip=None, start=None, end=None):
    df = _csv("network_logs")
    m = pd.Series(False, index=df.index)
    if src_ip: m |= df.src_ip == src_ip
    if dst_ip: m |= df.dst_ip == dst_ip
    df = df[m]
    if start: df = df[df.time >= start]
    if end:   df = df[df.time <= end]
    return df.to_dict("records")

def detect_bruteforce(rows):
    fails = [r for r in rows if r["event"] == "login_failed"]
    by_ip = {}
    for r in fails: by_ip.setdefault(r["src_ip"], []).append(r)
    out = []
    for ip, f in by_ip.items():
        if len(f) >= 10:
            succ = [r for r in rows if r["event"] == "login_success" and r["src_ip"] == ip and r["time"] >= f[0]["time"]]
            out.append({"type": "bruteforce", "ip": ip, "failed": len(f), "followed_by_success": bool(succ),
                        "success_geo": succ[0]["geo"] if succ else None})
    return out

def detect_lateral(rows):
    return [{"type": "lateral_movement", "host": r["host"], "from": r["src_ip"], "time": r["time"]}
            for r in rows if r["event"] == "login_success" and r["host"].startswith("SRV") and r["src_ip"].startswith("10.0.") and r["geo"] == "PK"]

def detect_beaconing(rows):
    by = {}
    for r in rows: by.setdefault(r["dst_ip"], []).append(datetime.strptime(r["time"], FMT))
    out = []
    for dst, t in by.items():
        if len(t) >= 10:
            iv = [(b - a).total_seconds() for a, b in zip(t, t[1:])]
            if statistics.pstdev(iv) < 0.15 * statistics.mean(iv):
                out.append({"type": "beaconing", "dst_ip": dst, "count": len(t), "interval_s": round(statistics.mean(iv))})
    return out

def detect_exfil(rows, threshold_mb=500):
    by = {}
    for r in rows: by[r["dst_ip"]] = by.get(r["dst_ip"], 0) + int(r["bytes_out"])
    return [{"type": "exfiltration", "dst_ip": d, "mb": round(b / 1e6)} for d, b in by.items() if b / 1e6 >= threshold_mb]

# ---------- Threat intel ----------
def lookup_ip(ip):
    for e in _json("threat_intel"):
        if e["ip"] == ip: return e
    key = os.getenv("ABUSEIPDB_KEY")   # optional live enrichment
    if key and ip and not ip.startswith("10."):
        try:
            req = urllib.request.Request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers={"Key": key, "Accept": "application/json"})
            d = json.load(urllib.request.urlopen(req, timeout=5))["data"]
            return {"ip": ip, "reputation": "malicious" if d["abuseConfidenceScore"] > 50 else "clean", "tags": "abuseipdb", "source": "abuseipdb"}
        except Exception: pass
    return {"ip": ip, "reputation": "unknown", "tags": "", "source": "none"}

MITRE = {
    "Multiple Failed Logins": ("T1110", "Brute Force"), "Login From New Country": ("T1078", "Valid Accounts"),
    "Lateral Movement Suspected": ("T1021", "Remote Services"), "Suspicious Email Attachment": ("T1566.001", "Spearphishing Attachment"),
    "PowerShell Encoded Command": ("T1059.001", "PowerShell"), "Beaconing Detected": ("T1071", "C2 over App Layer Protocol"),
    "Large Outbound Transfer": ("T1048", "Exfiltration Over Alt Protocol"), "Unusual DB Export": ("T1005", "Data from Local System"),
    "Ransomware Behaviour": ("T1486", "Data Encrypted for Impact"),
}
def map_mitre(rule): return MITRE.get(rule)
