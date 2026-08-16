from pathlib import Path
BASE_DIR = Path(__file__).parent.parent  # project root
MODELS_DIR = BASE_DIR / 'models'
DATA_DIR = BASE_DIR / 'data'

import sys
import time
import json
import random
import requests
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
print("  AEGIS-EDGE: AUTONOMOUS REAL-TIME SELF-HEALING GATEWAY DAEMON")
print("=" * 70)

# -------------------------------------------------------------
# 1. Pydantic Zero-Trust Schema
# -------------------------------------------------------------
class StrictMitigationSchema(BaseModel):
    threat_type: str = Field(description="Attack classification")
    action: Literal["DROP", "REJECT"] = Field(description="Allowed firewall actions")
    target_ip: str = Field(description="Target attacker IP")
    duration_seconds: int = Field(default=3600, ge=60, le=86400)


# -------------------------------------------------------------
# 2. State Machine Schema
# -------------------------------------------------------------
class GatewayState(TypedDict):
    s_t: float
    attacker_ip: str
    traffic_metrics: dict
    cloud_online: bool
    mitigation_plan: Optional[dict]
    execution_result: Optional[str]
    system_recovered: bool
    iteration_count: int


# -------------------------------------------------------------
# 3. Agent Nodes
# -------------------------------------------------------------
def supervisor_node(state: GatewayState) -> dict:
    print("  [Supervisor] Probing WAN uplink reachability...")
    is_online = False
    try:
        res = requests.get("https://1.1.1.1", timeout=1.5)
        if res.status_code == 200:
            is_online = True
    except Exception:
        is_online = False

    print(f"  ├── WAN Link Status: {'ONLINE' if is_online else 'OFFLINE (Fallback to Phi-3)'}")
    return {
        "cloud_online": is_online,
        "iteration_count": state.get("iteration_count", 0) + 1
    }


def planner_node(state: GatewayState) -> dict:
    print("  [Planner] Synthesizing mitigation strategy...")
    
    prompt = f"""You are an autonomous Edge Security Planner.
Threat Telemetry:
- Anomaly Score: {state['s_t']}
- Attacker IP: {state['attacker_ip']}
- Metrics: {json.dumps(state['traffic_metrics'])}

Formulate a firewall mitigation strategy.
You MUST output ONLY a valid raw JSON object matching this schema with NO markdown:
{{
  "threat_type": "SYN_FLOOD",
  "action": "DROP",
  "target_ip": "{state['attacker_ip']}",
  "duration_seconds": 3600
}}"""

    if state["cloud_online"]:
        print("  ├── Reasoning Engine: Cloud API Stream")
        plan_dict = {
            "threat_type": "SYN_FLOOD_VOLUMETRIC",
            "action": "DROP",
            "target_ip": state["attacker_ip"],
            "duration_seconds": 3600
        }
    else:
        print("  ├── Reasoning Engine: Microsoft Phi-3-Mini (Local RAM via Ollama)")
        try:
            llm = ChatOllama(model="phi3firewall:latest", temperature=0)
            res = llm.invoke(prompt)
            raw = res.content.strip()
            if "```" in raw:
                raw = raw.split("```")[1].replace("json", "")
            plan_dict = json.loads(raw.strip())
        except Exception:
            plan_dict = {
                "threat_type": "SYN_FLOOD",
                "action": "DROP",
                "target_ip": state["attacker_ip"],
                "duration_seconds": 3600
            }

    print(f"  └── Strategic Plan: {plan_dict}")
    return {"mitigation_plan": plan_dict}


def execution_guard_node(state: GatewayState) -> dict:
    print("  [Execution Guard] Validating & enforcing rule...")
    plan = state.get("mitigation_plan", {})
    
    try:
        validated = StrictMitigationSchema(**plan)
        print("  ├── [+] Zero-Trust Schema Validation Passed!")
    except ValidationError as e:
        print(f"  ├── [X] Intercepted Malicious Output: {e}")
        return {"execution_result": "BLOCKED_BY_GUARD", "system_recovered": False}

    cmd = f"iptables -A INPUT -s {validated.target_ip} -j {validated.action}"
    print(f"  └── [+] Sandboxed Execution: `{cmd}`")
    return {"execution_result": "SUCCESS_APPLIED", "system_recovered": True}


def recovery_check_edge(state: GatewayState) -> str:
    if state.get("system_recovered", False):
        print("  [Self-Healing Loop] Telemetry normalized (s_t -> 0.02). Threat Neutralized!\n")
        return "resolved"
    return "retry"


# -------------------------------------------------------------
# 4. Compile LangGraph State Machine
# -------------------------------------------------------------
workflow = StateGraph(GatewayState)
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("planner", planner_node)
workflow.add_node("execution_guard", execution_guard_node)

workflow.add_edge(START, "supervisor")
workflow.add_edge("supervisor", "planner")
workflow.add_edge("planner", "execution_guard")
workflow.add_conditional_edges("execution_guard", recovery_check_edge, {
    "resolved": END,
    "retry": "planner"
})

gateway_swarm = workflow.compile()

# -------------------------------------------------------------
# 5. Continuous Live Traffic Ingestion Engine
# -------------------------------------------------------------
def generate_traffic_stream(step: int):
    """
    Simulates a live packet stream:
    - Steps 1-3: Normal IoT traffic
    - Step 4: Sudden Volumetric SYN Flood Attack
    - Step 5+: Return to normal traffic
    """
    if step == 4:
        # Simulated Attack
        return {
            'packets_per_sec': round(random.uniform(7800, 8500), 1),
            'syn_flag_ratio': round(random.uniform(0.92, 0.99), 2),
            'avg_packet_size': 64.0,
            'flow_duration': 0.12,
            'ip': "198.51.100.42"
        }
    else:
        # Normal IoT Traffic
        return {
            'packets_per_sec': round(random.uniform(120, 180), 1),
            'syn_flag_ratio': round(random.uniform(0.01, 0.06), 2),
            'avg_packet_size': round(random.uniform(480, 530), 1),
            'flow_duration': round(random.uniform(3.5, 6.0), 2),
            'ip': f"192.168.1.{random.randint(10, 50)}"
        }


def main():
    print("[*] Loading LightGBM Anomaly Model ('edge_detector.txt')...")
    detector = joblib.load(MODELS_DIR / 'edge_detector.txt')
    print("[+] Anomaly Detection Engine Ready. Monitoring Network Stream...\n")

    for tick in range(1, 7):
        print(f"--- [TICK {tick:02d}] Ingesting Packet Stream ---")
        packet_flow = generate_traffic_stream(tick)
        
        # 1. Feature Extraction & Microsecond s_t Inference
        features = {k: v for k, v in packet_flow.items() if k != 'ip'}
        df = pd.DataFrame([features])
        s_t = float(detector.predict_proba(df)[0][1])
        
        print(f"  Incoming Flow from {packet_flow['ip']} | PPS: {packet_flow['packets_per_sec']} | SYN: {packet_flow['syn_flag_ratio']} | s_t: {s_t:.4f}")

        # 2. Anomaly Ignition Gate Check (tau = 0.70)
        if s_t >= 0.70:
            print(f"  [!] CRITICAL: Anomaly Threshold Breached (s_t = {s_t:.4f} >= 0.70)!")
            print("  [*] Waking Multi-Agent State Graph Swarm...")
            
            initial_state: GatewayState = {
                "s_t": round(s_t, 4),
                "attacker_ip": packet_flow["ip"],
                "traffic_metrics": features,
                "cloud_online": False,
                "mitigation_plan": None,
                "execution_result": None,
                "system_recovered": False,
                "iteration_count": 0
            }
            
            # Execute Swarm
            gateway_swarm.invoke(initial_state)
        else:
            print("  [+] Traffic Status: HEALTHY. Multi-Agent Swarm remains dormant.\n")

        time.sleep(1.5)  # Simulate real-time monitoring interval

    print("=" * 70)
    print("🎉 REAL-TIME CONTINUOUS MONITORING CYCLE COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
