import pandas as pd, streamlit as st
from graph import run_pipeline
import tools as T

st.set_page_config(page_title="AutoSOC - Multi-Agent Incident Investigation", layout="wide")
st.title("🛡️ AutoSOC: Autonomous Cybersecurity Incident Investigation")
st.caption("6 collaborating agents: Triage → Log Analyst → Threat Intel → Investigator → Response → Reporter")

if st.button("▶ Run investigation on today's alerts", type="primary"):
    with st.spinner("Agents are investigating..."):
        st.session_state["res"] = run_pipeline()

res = st.session_state.get("res")
if res:
    inc = res["incidents"]; tot = len(T.load_alerts())
    c = st.columns(4)
    c[0].metric("Raw alerts", tot); c[1].metric("Auto-suppressed (noise)", len(res["suppressed"]))
    c[2].metric("Incidents investigated", len(inc))
    c[3].metric("Confirmed threats", sum(i.get("verdict") == "TRUE_POSITIVE" for i in inc))
    tab1, tab2, tab3 = st.tabs(["Incident reports", "Agent conversation", "Suppressed alerts"])
    with tab1:
        for i in inc:
            icon = {"TRUE_POSITIVE": "🔴", "FALSE_POSITIVE": "🟢", "NEEDS_MORE_INFO": "🟠"}[i["verdict"]]
            with st.expander(f"{icon} {i['id']} | {i['entity']} | {i['verdict']} | {i['priority']}", expanded=i["verdict"] != "FALSE_POSITIVE"):
                st.markdown(i["report"])
    with tab2:
        for m in res["messages"]: st.markdown(f"**{m['from']} → {m['to']}**: {m['text']}")
    with tab3:
        st.dataframe(pd.DataFrame(res["suppressed"])[["alert_id", "rule", "severity", "why"]])
