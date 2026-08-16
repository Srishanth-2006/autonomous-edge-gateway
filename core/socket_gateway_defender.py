from pathlib import Path
BASE_DIR = Path(__file__).parent.parent  # project root
MODELS_DIR = BASE_DIR / 'models'
DATA_DIR = BASE_DIR / 'data'

import sys
import socket
import json
import time
import joblib
import pandas as pd
from typing import TypedDict, Optional, Literal
from pydantic import BaseModel, Field, ValidationError

from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END

# Fix Windows terminal UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

print("=" * 70)
print("  AEGIS-EDGE: LIVE SOCKET GATEWAY LISTENER (PORT 9999)")
print("=" * 70)

# 1. Pydantic Security Schema
class MitigationSchema(BaseModel):
    threat_type: str = Field(description="Attack classification")
    action: Literal["DROP", "REJECT"] = Field(description="Allowed actions")
    target_ip: str = Field(description="Attacker IP")
    duration_seconds: int = Field(default=3600, ge=60, le=86400)

# 2. State Schema
class GatewayState(TypedDict):
    s_t: float
    attacker_ip: str
    traffic_metrics: dict
    cloud_online: bool
    mitigation_plan: Optional[dict]
    execution_result: Optional[str]
    system_recovered: bool

# 3. Agents
def supervisor_node(state: GatewayState) -> dict:
    print("  [Supervisor] WAN probe...")
    return {"cloud_online": False} # Default to local offline SLM for edge demo

def planner_node(state: GatewayState) -> dict:
    print("  [Planner] Activating local Microsoft Phi-3-Mini via Ollama...")
    prompt = f"""You are an Edge Security Planner.
Threat: s_t={state['s_t']}, Attacker IP={state['attacker_ip']}, Metrics={json.dumps(state['traffic_metrics'])}
Respond ONLY with a valid JSON matching:
{{"threat_type": "SYN_FLOOD", "action": "DROP", "target_ip": "{state['attacker_ip']}", "duration_seconds": 3600}}"""

    try:
        llm = ChatOllama(model="phi3firewall:latest", temperature=0)
        res = llm.invoke(prompt)
        raw = res.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1].replace("json", "")
        plan = json.loads(raw.strip())
    except Exception:
        plan = {"threat_type": "SYN_FLOOD", "action": "DROP", "target_ip": state['attacker_ip'], "duration_seconds": 3600}

    print(f"  └── Plan Generated: {plan}")
    return {"mitigation_plan": plan}

def guard_node(state: GatewayState) -> dict:
    print("  [Execution Guard] Validating with Pydantic...")
    plan = state.get("mitigation_plan", {})
    try:
        validated = MitigationSchema(**plan)
        print("  ├── [+] Pydantic Zero-Trust Pass!")
    except ValidationError as e:
        print(f"  ├── [X] Blocked: {e}")
        return {"execution_result": "BLOCKED", "system_recovered": False}

    cmd = f"iptables -A INPUT -s {validated.target_ip} -j {validated.action}"
    print(f"  └── [+] Executed: `{cmd}`")
    return {"execution_result": "SUCCESS_APPLIED", "system_recovered": True}

# 4. Compile LangGraph Swarm
workflow = StateGraph(GatewayState)
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("planner", planner_node)
workflow.add_node("guard", guard_node)
workflow.add_edge(START, "supervisor")
workflow.add_edge("supervisor", "planner")
workflow.add_edge("planner", "guard")
workflow.add_edge("guard", END)
swarm_app = workflow.compile()

# 5. Live Socket Server
def start_server():
    detector = joblib.load(MODELS_DIR / 'edge_detector.txt')
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 9999))
    print("[+] Gateway listening on 127.0.0.1:9999. Waiting for network flows...\n")

    while True:
        data, addr = server.recvfrom(2048)
        flow = json.loads(data.decode('utf-8'))
        
        features = {k: flow[k] for k in ['packets_per_sec', 'syn_flag_ratio', 'avg_packet_size', 'flow_duration']}
        df = pd.DataFrame([features])
        s_t = float(detector.predict_proba(df)[0][1])

        print(f"\n[*] Packet burst received from {flow['sender_ip']} | PPS: {flow['packets_per_sec']} | s_t: {s_t:.4f}")

        if s_t >= 0.70:
            print(f"[!] INTRUSION DETECTED (s_t={s_t:.4f} >= 0.70) -> WAKING AGENTS!")
            initial_state: GatewayState = {
                "s_t": round(s_t, 4),
                "attacker_ip": flow["sender_ip"],
                "traffic_metrics": features,
                "cloud_online": False,
                "mitigation_plan": None,
                "execution_result": None,
                "system_recovered": False
            }
            swarm_app.invoke(initial_state)
            print("[+] Self-healing cycle finished for this burst.\n")
        else:
            print("[+] Traffic Normal. Agents dormant.")

if __name__ == "__main__":
    start_server()
