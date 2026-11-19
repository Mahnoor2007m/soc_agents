"""Synthetic SOC dataset: alerts, auth logs, network logs, threat-intel, assets.
Contains 4 real attack scenarios hidden among false positives + one incomplete-data case."""
import random, json, csv
from datetime import datetime, timedelta
random.seed(7)
T0 = datetime(2026, 11, 18, 8, 0, 0)
def ts(m): return (T0 + timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M:%S")

users = ["ali","sara","bilal","hina","usman","zara","omar","admin","svc_backup","dev_ahmed"]
hosts = {f"WS-{i:03d}": u for i, u in enumerate(users, 1)}
hosts.update({"SRV-DB01":"-","SRV-WEB01":"-","SRV-FILE01":"-"})
internal = {h: f"10.0.{i//250}.{i%250+10}" for i, h in enumerate(hosts)}
BAD_IPS = ["185.220.101.45","45.155.205.233","91.240.118.172","194.26.29.102"]
GOOD_EXT = ["142.250.77.14","20.190.159.4","52.96.108.18","151.101.1.69"]

assets = [{"host":h,"ip":internal[h],"owner":hosts[h],
           "criticality":"critical" if h.startswith("SRV-DB") else "high" if h.startswith("SRV") else "medium"} for h in hosts]
intel = [{"ip":ip,"reputation":"malicious","tags":t,"source":"local-feed"} for ip,t in
         zip(BAD_IPS,["tor-exit,bruteforce","c2-server","phishing-host","ransomware-c2"])]

auth, net, alerts = [], [], []
aid = 0
def alert(m, rule, sev, user=None, host=None, ip=None, desc=""):
    global aid; aid += 1
    alerts.append(dict(alert_id=f"A{aid:04d}", time=ts(m), rule=rule, severity=sev,
                       user=user or "", host=host or "", src_ip=ip or "", description=desc))

# ---- noise: normal activity + false-positive alerts
for m in range(0, 600, 2):
    u = random.choice(users); h = next(k for k,v in hosts.items() if v==u)
    auth.append(dict(time=ts(m), user=u, host=h, src_ip=internal[h], event="login_success", geo="PK"))
    net.append(dict(time=ts(m), src_ip=internal[h], dst_ip=random.choice(GOOD_EXT), dst_port=443, bytes_out=random.randint(500,60000)))
for _ in range(150):
    m = random.randint(0, 600); kind = random.choice(["fp_scan","fp_fail","fp_admin","fp_update","fp_geo"])
    if kind=="fp_scan":   alert(m,"Port Scan Detected","medium",host="SRV-WEB01",ip="10.0.0.5",desc="Scan from internal vuln-scanner Nessus (10.0.0.5)")
    if kind=="fp_fail":
        u=random.choice(users); alert(m,"Failed Login","low",user=u,desc="1 failed login (typo)")
        auth.append(dict(time=ts(m),user=u,host="-",src_ip="10.0.0.20",event="login_failed",geo="PK"))
    if kind=="fp_admin": alert(m,"Admin Login Off-Hours","medium",user="admin",host="SRV-FILE01",ip="10.0.0.8",desc="Admin login via corporate VPN")
    if kind=="fp_update":alert(m,"Large Outbound Transfer","medium",host="WS-003",ip=internal["WS-003"],desc="Windows update download pattern")
    if kind=="fp_geo":   alert(m,"Unusual Geo Login","low",user=random.choice(users),ip="20.190.159.4",desc="Microsoft 365 sign-in")

# ---- Scenario 1: brute force -> successful login -> lateral movement (user: bilal)
for k in range(40):
    auth.append(dict(time=ts(200+k*0.2),user="bilal",host="WS-003",src_ip=BAD_IPS[0],event="login_failed",geo="DE"))
auth.append(dict(time=ts(209),user="bilal",host="WS-003",src_ip=BAD_IPS[0],event="login_success",geo="DE"))
auth.append(dict(time=ts(214),user="bilal",host="SRV-FILE01",src_ip=internal["WS-003"],event="login_success",geo="PK"))
alert(201,"Multiple Failed Logins","high",user="bilal",ip=BAD_IPS[0],desc="40 failed logins in 8 minutes")
alert(209,"Login From New Country","high",user="bilal",ip=BAD_IPS[0],desc="Successful login from DE")
alert(214,"Lateral Movement Suspected","critical",user="bilal",host="SRV-FILE01",ip=internal["WS-003"],desc="Workstation to file server login")

# ---- Scenario 2: phishing -> malware -> C2 beaconing (host WS-006 / user zara)
alert(300,"Suspicious Email Attachment","medium",user="zara",host="WS-006",desc="Macro-enabled .docm opened")
alert(303,"PowerShell Encoded Command","high",user="zara",host="WS-006",ip=internal["WS-006"],desc="powershell -enc ... spawned by WINWORD.EXE")
for k in range(30):
    net.append(dict(time=ts(305+k*5),src_ip=internal["WS-006"],dst_ip=BAD_IPS[1],dst_port=8443,bytes_out=random.randint(180,260)))
alert(320,"Beaconing Detected","high",host="WS-006",ip=internal["WS-006"],desc="Periodic 5-min connections to 45.155.205.233")

# ---- Scenario 3: data exfiltration from DB (user: dev_ahmed)
auth.append(dict(time=ts(400),user="dev_ahmed",host="SRV-DB01",src_ip=internal["WS-010"],event="login_success",geo="PK"))
for k in range(6):
    net.append(dict(time=ts(402+k),src_ip=internal["SRV-DB01"],dst_ip=BAD_IPS[2],dst_port=443,bytes_out=random.randint(350_000_000,600_000_000)))
alert(405,"Large Outbound Transfer","critical",user="dev_ahmed",host="SRV-DB01",ip=internal["SRV-DB01"],desc="2.8 GB sent to external IP")
alert(406,"Unusual DB Export","high",user="dev_ahmed",host="SRV-DB01",desc="Full table dump executed")

# ---- Scenario 4: INCOMPLETE DATA (alert exists, no logs) -> agent must request more / lower confidence
alert(500,"Ransomware Behaviour","high",host="WS-007",ip=internal["WS-007"],desc="Mass file rename .locked (EDR telemetry only, logs missing)")

# ---- Scenario 5: tricky false positive that LOOKS bad (legit travel, MFA passed)
auth.append(dict(time=ts(100),user="hina",host="WS-004",src_ip="20.190.159.4",event="login_success",geo="AE"))
alert(100,"Login From New Country","high",user="hina",ip="20.190.159.4",desc="Login from AE, MFA passed, user on approved travel")

random.shuffle(alerts)
alerts.sort(key=lambda a:a["time"])
for i,a in enumerate(alerts,1): a["alert_id"]=f"A{i:04d}"
auth.sort(key=lambda r:r["time"]); net.sort(key=lambda r:r["time"])

def dump(name, rows):
    with open(f"data/{name}.csv","w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
dump("alerts",alerts); dump("auth_logs",auth); dump("network_logs",net); dump("assets",assets)
json.dump(intel,open("data/threat_intel.json","w"),indent=2)
json.dump({"scanner_ips":["10.0.0.5"],"vpn_ips":["10.0.0.8"],"approved_travel":["hina"],
           "trusted_domains":["microsoft.com","google.com"]},open("data/allowlist.json","w"),indent=2)
print(f"alerts={len(alerts)} auth={len(auth)} net={len(net)} assets={len(assets)}")
