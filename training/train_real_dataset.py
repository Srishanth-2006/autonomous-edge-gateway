# train_real_dataset.py
from pathlib import Path
BASE_DIR = Path(__file__).parent.parent  # project root
MODELS_DIR = BASE_DIR / 'models'
DATA_DIR = BASE_DIR / 'data'
import sys
import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Fix Windows terminal UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

print("=" * 70)
print("  PHASE 2 (REAL DATA): TRAINING LIGHTGBM ON CIC-IDS2017 DATASET")
print("=" * 70)

CSV_FILENAME = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

if not os.path.exists(CSV_FILENAME):
    print(f"\n[!] Error: Dataset file '{CSV_FILENAME}' not found in the current folder.")
    print("    Please download it from Kaggle and place it in this directory.")
    sys.exit(1)

print(f"[*] Ingesting raw network flow dataset: '{CSV_FILENAME}'...")
# Ingest dataset (reading 100,000 balanced rows for fast edge training)
raw_df = pd.read_csv(CSV_FILENAME, nrows=100000)

# Strip any whitespace from column names
raw_df.columns = raw_df.columns.str.strip()

print(f"[+] Successfully loaded {len(raw_df):,} raw network flows.")

# -------------------------------------------------------------
# 1. Feature Extraction & Cleaning
# -------------------------------------------------------------
print("\n[*] Extracting the 4 core Edge Telemetry features...")

# Map dataset columns to our 4 features
feature_mapping = {
    'Flow Packets/s': 'packets_per_sec',
    'SYN Flag Count': 'syn_flag_ratio',
    'Average Packet Size': 'avg_packet_size',
    'Flow Duration': 'flow_duration'
}

# Ensure columns exist
selected_cols = list(feature_mapping.keys())
df = raw_df[selected_cols + ['Label']].copy()

# Rename to our standardized edge feature names
df.rename(columns=feature_mapping, inplace=True)

# Convert infinite or NaN values that often occur in raw network captures
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Encode Labels: 0 = Benign/Safe, 1 = Attack (DDoS / Anomaly)
df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

X = df[['packets_per_sec', 'syn_flag_ratio', 'avg_packet_size', 'flow_duration']]
y = df['Label'].values

print(f"  ├── Clean Samples : {len(df):,}")
print(f"  ├── Benign Flows  : {np.sum(y == 0):,} ({(np.sum(y == 0)/len(y))*100:.1f}%)")
print(f"  └── Malicious/DDoS: {np.sum(y == 1):,} ({(np.sum(y == 1)/len(y))*100:.1f}%)")

# -------------------------------------------------------------
# 2. Train-Test Split & Training
# -------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

print("\n[*] Training Edge LightGBM Decision Tree Ensemble...")
start_train = time.perf_counter()

model = HistGradientBoostingClassifier(
    loss='log_loss',
    learning_rate=0.05,
    max_iter=60,
    max_leaf_nodes=15,
    random_state=42
)
model.fit(X_train, y_train)

train_duration = time.perf_counter() - start_train
print(f"[+] Model Trained in {train_duration:.2f} seconds.")

# -------------------------------------------------------------
# 3. Model Evaluation on Real Test Split
# -------------------------------------------------------------
y_pred_proba = model.predict_proba(X_test)[:, 1]
y_pred = (y_pred_proba >= 0.70).astype(int)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc = roc_auc_score(y_test, y_pred_proba)

print("\n" + "-" * 40)
print("  EVALUATION METRICS ON REAL NETWORK TEST DATA")
print("-" * 40)
print(f"  ├── Accuracy    : {acc * 100:.2f}%")
print(f"  ├── Precision   : {prec * 100:.2f}%")
print(f"  ├── Recall (TPR): {rec * 100:.2f}%")
print(f"  ├── F1-Score    : {f1:.4f}")
print(f"  └── ROC-AUC     : {roc:.4f}")

# Save the newly trained model
MODELS_DIR.mkdir(parents=True, exist_ok=True)
model_out = MODELS_DIR / 'edge_detector.txt'
joblib.dump(model, model_out)
model_size = model_out.stat().st_size / 1024.0
print(f"\n[+] Production model saved as '{model_out}' ({model_size:.2f} KB)")

# -------------------------------------------------------------
# 4. Live Real-World Evaluation Test Cases
# -------------------------------------------------------------
print("\n" + "=" * 70)
print("  REAL-WORLD TRAFFIC INFERENCE TEST CASES")
print("=" * 70)

# Sample 2 real benign flows and 2 real attack flows from the test set
sample_benign = X_test[y_test == 0].iloc[0:2]
sample_attack = X_test[y_test == 1].iloc[0:2]

test_cases = [
    {"name": "Real IoT Traffic Flow A (Safe)", "features": sample_benign.iloc[0].to_dict(), "expected": "SAFE"},
    {"name": "Real IoT Traffic Flow B (Safe)", "features": sample_benign.iloc[1].to_dict(), "expected": "SAFE"},
    {"name": "Real Volumetric Flood A (DDoS)", "features": sample_attack.iloc[0].to_dict(), "expected": "ATTACK"},
    {"name": "Real Volumetric Flood B (DDoS)", "features": sample_attack.iloc[1].to_dict(), "expected": "ATTACK"},
]

for tc in test_cases:
    input_df = pd.DataFrame([tc["features"]])
    s_t = float(model.predict_proba(input_df)[0][1])
    alarm = s_t >= 0.70
    
    print(f"\n[*] {tc['name']}")
    print(f"    Metrics     : PPS={tc['features']['packets_per_sec']:.1f} | SYN%={tc['features']['syn_flag_ratio']} | AvgBytes={tc['features']['avg_packet_size']:.1f}")
    print(f"    Score (s_t) : {s_t:.4f} (Threshold tau = 0.70)")
    print(f"    Action      : {'[!] WAKE MULTI-AGENT SWARM' if alarm else '[+] SLEEP / DORMANT'}")
    print(f"    Verification: {'CORRECT CLASSIFICATION' if (alarm == (tc['expected'] == 'ATTACK')) else 'INCORRECT'}")

print("\n" + "=" * 70)
print("🎉 REAL-WORLD TRAINING & TEST SUITE COMPLETED!")
print("=" * 70)
