import json
from collections import Counter
from graph import run_pipeline

s = run_pipeline()
inc = s["incidents"]
print("\n=== AGENT CONVERSATION ===")
for m in s["messages"]:
    print(f"[{m['from']} -> {m['to']}] {m['text']}")
print("\n=== INCIDENT REPORTS ===")
for i in inc:
    if "report" in i:
        print(i["report"], "\n")
print("Verdict summary:", Counter(i.get("verdict", "(not investigated)") for i in inc))
json.dump({k: v for k, v in s.items() if k != "current"}, open("output.json", "w"), indent=1, default=str)
