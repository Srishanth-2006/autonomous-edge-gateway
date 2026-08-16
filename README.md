# AEGIS-EDGE: Autonomous Edge Gateway with Dual-Engine AI

> An autonomous cybersecurity gateway that uses a **LightGBM anomaly detector** + **Dual-Engine AI decision system** (Google Gemini Cloud + Fine-Tuned Local Phi-3) to detect and mitigate network threats in real-time — even without internet connectivity.

---

## Architecture

```
Network Traffic
      │
      ▼
┌─────────────────────┐
│  LightGBM Detector  │  ← Fast ML anomaly scoring (edge_detector.txt)
│   (Anomaly Score)   │
└────────┬────────────┘
         │ s_t ≥ 0.70 (threat detected)
         ▼
┌─────────────────────────────────────────────────────────┐
│              LangGraph Multi-Agent State Machine         │
│                                                         │
│  [Supervisor] → [Planner] → [Execution Guard]           │
│                    │                                     │
│              WAN Online?                                 │
│             /          \                                 │
│    Gemini Cloud AI    Local Phi-3 AI                    │
│   (gemini-flash)    (phi3firewall:latest)               │
│             \          /                                 │
│         Pydantic Zero-Trust Validation                  │
│                    │                                     │
│            iptables Firewall Rule                       │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
autonomous_edge_gateway/
├── core/                          # Gateway & detection scripts
│   ├── dual_engine_gateway.py     # PRIMARY: Dual-engine AI gateway
│   ├── agent_gateway.py           # Phase 3: LangGraph state machine
│   ├── live_gateway_engine.py     # Real-time packet stream gateway
│   ├── socket_gateway_defender.py # UDP socket-based defender
│   └── detector.py                # LightGBM detector module
│
├── models/                        # Pre-trained model artifacts
│   ├── edge_detector.txt          # Trained LightGBM model
│   ├── Modelfile                  # Ollama Modelfile for phi3firewall
│   └── phi3_firewall_lora/        # Fine-tuned LoRA adapter weights
│
├── data/                          # Training datasets
│   └── hybrid_phi3_train.jsonl    # Phi-3 fine-tuning dataset (JSONL)
│
├── training/                      # Model training scripts
│   └── train_real_dataset.py      # LightGBM detector training
│
├── .env.example                   # Environment variable template
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed and running
- Google Gemini API key from [aistudio.google.com](https://aistudio.google.com)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set Up Environment
```bash
cp .env.example .env
# Edit .env and add your GOOGLE_API_KEY
```

### 4. Download & Register Fine-Tuned Model
Download `phi3_firewall_q4km.gguf` and place it in `models/`, then register it with Ollama:
```bash
ollama create phi3firewall:latest -f models/Modelfile
```

### 5. Run the Dual-Engine Gateway
```bash
python core/dual_engine_gateway.py
```

---

## Test Scenarios

The gateway runs two automatic test scenarios:

| Scenario | WAN Status | Engine Used | Expected Output |
|---|---|---|---|
| 1 | Online | Google Gemini Flash | `SYN_FLOOD → DROP` |
| 2 | Offline | Local phi3firewall | `SYN_FLOOD → DROP` |

---

## Key Features

- **Hybrid AI Architecture**: Cloud Gemini + Local Phi-3 with automatic failover
- **Zero-Trust Security**: Pydantic schema validation blocks prompt injection
- **Autonomous Operation**: Self-healing without human intervention
- **Offline Resilience**: Full operation even when internet is severed
- **Multi-Model Retry**: Auto-retries across 4 Gemini model variants on overload
- **Real-Time Detection**: LightGBM scores traffic in <1ms

---

## Model Details

| Component | Details |
|---|---|
| Anomaly Detector | LightGBM trained on CIC-IDS2017 (DDoS flows) |
| Cloud LLM | Google Gemini Flash (via `google.genai` SDK) |
| Local LLM | Microsoft Phi-3-mini-4k fine-tuned with QLoRA (4-bit Q4_K_M GGUF) |
| Fine-Tuning Dataset | `hybrid_phi3_train.jsonl` (cybersecurity Q&A pairs) |
| Validation | Pydantic v2 Zero-Trust schema enforcement |

---

## Note on Large Files

The following files are excluded from this repository due to size:
- `models/phi3_firewall_q4km.gguf` (~2.3 GB) — Download from Kaggle/HuggingFace
- `data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (~77 MB) — [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

---

## Tech Stack

`Python` · `LightGBM` · `LangGraph` · `LangChain` · `Ollama` · `Phi-3-mini` · `Google Gemini` · `Pydantic` · `GGUF` · `QLoRA`
