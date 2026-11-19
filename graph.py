"""Orchestrator. Uses LangGraph when installed (conditional edge = adaptive retry loop);
otherwise falls back to an equivalent built-in runner so the project always runs."""
import copy
from agents.core import *

def _investigate_nodes():
    return {"log": log_agent, "intel": intel_agent, "investigate": investigator_agent, "respond": response_agent, "report": reporter_agent}

def _route(state): return "log" if state["current"].get("retry") else "respond"

def run_incident_langgraph(state):
    from langgraph.graph import StateGraph, END
    g = StateGraph(dict); n = _investigate_nodes()
    for k, f in n.items(): g.add_node(k, f)
    g.set_entry_point("log"); g.add_edge("log", "intel"); g.add_edge("intel", "investigate")
    g.add_conditional_edges("investigate", _route, {"log": "log", "respond": "respond"})
    g.add_edge("respond", "report"); g.add_edge("report", END)
    return g.compile().invoke(state)

def run_incident_builtin(state):
    n = _investigate_nodes(); node = "log"
    while node != "END":
        state = n[node](state)
        node = {"log": "intel", "intel": "investigate", "investigate": _route(state) if True else "", "respond": "report", "report": "END"}[node]
    return state

def run_pipeline(top_n=None, use_langgraph=True, progress=None):
    state = {"messages": [], "incidents": [], "suppressed": [], "current": None}
    state = triage_agent(state)
    try:
        import langgraph; runner = run_incident_langgraph if use_langgraph else run_incident_builtin
    except ImportError: runner = run_incident_builtin
    for i, inc in enumerate(state["incidents"][:top_n] if top_n else state["incidents"]):
        state["current"] = inc
        state = runner(state)
        if progress: progress(i, inc)
    state["current"] = None
    return state
