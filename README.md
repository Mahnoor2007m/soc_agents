# AutoSOC – Autonomous Cybersecurity Incident Investigation (Multi-Agent)
Case Study 2. 160 daily alerts -> 150 noise auto-suppressed -> 5 incidents investigated by 6 agents.

## Run
pip install -r requirements.txt
python generate_data.py     # synthetic alerts + logs
python main.py              # CLI demo (prints agent conversation + reports)
streamlit run app.py        # UI demo

## Agents
| Agent | Job | Tools |
|---|---|---|
| Triage | dedupe, suppress known-benign, group alerts per entity, rank | allowlist, asset inventory |
| Log Analyst | search auth/network logs, detect patterns | query_auth_logs, query_network_logs, detect_bruteforce/beaconing/exfil/lateral |
| Threat Intel | IP reputation, MITRE ATT&CK mapping | local feed, optional AbuseIPDB API (ABUSEIPDB_KEY) |
| Investigator | correlates evidence, weighs benign vs malicious, verdict + confidence, may request more logs | risk scoring, asset criticality |
| Response | playbook actions, marks destructive ones "human approval" | playbooks |
| Reporter | incident report | templates |

## Handling unexpected / incomplete information
- Alert with no logs (INC-005 ransomware, EDR only): Investigator sends message back to Log Analyst, widens search, then returns NEEDS_MORE_INFO (0.4 confidence) and escalates cautiously.
- Look-alike false positive (hina, login from AE): approved travel + no malicious indicators -> FALSE_POSITIVE.
- Threat-intel miss/unknown IP: falls back to "unknown", never crashes; live API optional.
