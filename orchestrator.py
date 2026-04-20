from typing import TypedDict, List
from langgraph.graph import StateGraph, END

# Define the Agent State
class AgentState(TypedDict):
    target_url: str
    raw_vulnerabilities: List[dict]
    context_data: dict
    ace_scores: List[dict]
    next_step: str

# Node 1: Discovery Agent (Simulated ingestion for now)
def discovery_node(state: AgentState):
    print("[*] Discovery Agent: Ingesting raw scan data...")
    # This will later call OWASP ZAP or Burp APIs [cite: 41, 43]
    return {"raw_vulnerabilities": [{"id": "SQLI_01", "name": "SQL Injection", "base_cvss": 8.8}]}

# Node 2: Context Agent
def context_node(state: AgentState):
    print("[*] Context Agent: Analyzing deployment environment...")
    # This checks for DCS (Deployment Context) and ASS (Auth State) [cite: 32, 44]
    return {"context_data": {"is_internet_facing": True, "has_waf": False, "auth_required": False}}

# Node 3: Scoring Agent (The ACE Engine)
def scoring_node(state: AgentState):
    print("[*] Scoring Agent: Computing ACE Index...")
    # This is where your custom formula lives [cite: 34, 46]
    vuln = state['raw_vulnerabilities'][0]
    ctx = state['context_data']
    
    # Simple ACE logic: (CVSS * 0.3) + Context Adjustments [cite: 34]
    ace_score = (vuln['base_cvss'] * 0.3) + (10 if ctx['is_internet_facing'] else 2) * 0.2
    return {"ace_scores": [{"id": vuln['id'], "score": round(ace_score, 2)}]}

# Build the Graph
workflow = StateGraph(AgentState)
workflow.add_node("discovery", discovery_node)
workflow.add_node("context", context_node)
workflow.add_node("scoring", scoring_node)

workflow.set_entry_point("discovery")
workflow.add_edge("discovery", "context")
workflow.add_edge("context", "scoring")
workflow.add_edge("scoring", END)

app = workflow.compile()
