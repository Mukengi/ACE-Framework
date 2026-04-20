import os
from typing import TypedDict, List
from langgraph.graph import StateGraph, END

# Import your sub-modules
from discovery_agent import run_nmap_discovery
from ace_engine import ACEScorer
from context_inspector import inspect_web_context

# 1. Define the Unified State Schema
class AgentState(TypedDict):
    target: str
    vulnerabilities: List[dict]
    context_data: dict
    final_results: List[dict]

# 2. Node: Discovery Agent
def discovery_node(state: AgentState):
    print("\n--- PHASE 1: DISCOVERY ---")
    raw_output = run_nmap_discovery(state['target'], "3000")
    
    found_vulns = []
    if "3000/tcp open" in raw_output:
        # Static anchor: Node.js Express (Juice Shop)
        found_vulns.append({
            "id": "WEB_SRV_3000",
            "name": "Node.js Express",
            "base_cvss": 7.5 
        })
    return {"vulnerabilities": found_vulns}

# 3. Node: Context Agent (The "Inspector")
def context_node(state: AgentState):
    print("--- PHASE 2: CONTEXT ENRICHMENT ---")
    # Real-time inspection of the target lab environment [cite: 69]
    target_url = f"http://{state['target']}:3000"
    real_context = inspect_web_context(target_url)
    
    return {
        "context_data": {
            "dcs": real_context['dcs'],
            "ass": real_context['ass'],
            "internet_facing": 10.0 # Standard assumption for Juice Shop lab
        }
    }

# 4. Node: Scoring Agent (ACE Computation)
def scoring_node(state: AgentState):
    print("--- PHASE 3: ACE COMPUTATION ---")
    scorer = ACEScorer()
    processed_results = []
    
    ctx = state['context_data']
    for vuln in state['vulnerabilities']:
        # ACE Formula = (CVSS x 0.3) + Contextual Dimensions 
        # We use mock values for ECP (0.22) and BLI (0.20) until those agents are built
        ace_score = scorer.calculate(
            base_cvss=vuln['base_cvss'],
            dcs=ctx['dcs'], 
            ass=ctx['ass'],
            ecp=7.5, # Placeholder for Exploit Chain Agent [cite: 32]
            bli=8.0  # Placeholder for Business Impact Agent [cite: 32]
        )
        
        priority = scorer.get_priority_band(ace_score)
        processed_results.append({
            "vulnerability": vuln['name'],
            "ace_index": ace_score,
            "priority": priority
        })
        
    return {"final_results": processed_results}

# 5. Graph Orchestration
workflow = StateGraph(AgentState)
workflow.add_node("discovery", discovery_node)
workflow.add_node("context", context_node)
workflow.add_node("scoring", scoring_node)

workflow.set_entry_point("discovery")
workflow.add_edge("discovery", "context")
workflow.add_edge("context", "scoring")
workflow.add_edge("scoring", END)

app = workflow.compile()

if __name__ == "__main__":
    inputs = {"target": "127.0.0.1"}
    for output in app.stream(inputs):
        for key, value in output.items():
            if key == "scoring":
                print(f"\n[!] ACE TRIAGE REPORT FOR {inputs['target']}:")
                for res in value['final_results']:
                    print(f" >> {res['vulnerability']} | ACE: {res['ace_index']} | PRIORITY: {res['priority']}")
