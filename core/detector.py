import sys
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
import joblib

# Fix Windows terminal UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

print("=" * 60)
print("  PHASE 2: Training LightGBM Edge Anomaly Detector (s_t)")
print("=" * 60)

# 1. Synthesize IoT Gateway Telemetry Data (Normal vs Attack)
np.random.seed(42)
n_samples = 10000

# Normal traffic distribution (Low packet rate, low SYN ratio, normal payload)
normal_pps = np.random.normal(loc=150, scale=40, size=n_samples // 2)        # ~150 packets/sec
normal_syn = np.random.uniform(low=0.01, high=0.10, size=n_samples // 2)     # 1-10% SYN packets
normal_bytes = np.random.normal(loc=512, scale=100, size=n_samples // 2)     # 512 bytes average
normal_duration = np.random.exponential(scale=5.0, size=n_samples // 2)      # Longer sessions

# Attack traffic distribution (SYN Flood / DoS: Huge packet rate, 90%+ SYN, tiny packets)
attack_pps = np.random.normal(loc=8000, scale=1200, size=n_samples // 2)     # ~8000 packets/sec
attack_syn = np.random.uniform(low=0.85, high=0.99, size=n_samples // 2)     # 85-99% SYN packets
attack_bytes = np.random.normal(loc=64, scale=10, size=n_samples // 2)       # 64-byte flood packets
attack_duration = np.random.exponential(scale=0.2, size=n_samples // 2)      # Short burst duration

# Combine into a structured DataFrame
features = pd.DataFrame({
    'packets_per_sec': np.clip(np.concatenate([normal_pps, attack_pps]), 0, None),
    'syn_flag_ratio': np.clip(np.concatenate([normal_syn, attack_syn]), 0, 1),
    'avg_packet_size': np.clip(np.concatenate([normal_bytes, attack_bytes]), 0, None),
    'flow_duration': np.clip(np.concatenate([normal_duration, attack_duration]), 0, None)
})

# Labels: 0 = Benign/Safe, 1 = Malicious/Attack
labels = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))

# 2. Split into Train & Test sets
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

# 3. Train the Histogram-based GBDT Model (Scikit-Learn's native LightGBM algorithm)
model = HistGradientBoostingClassifier(
    loss='log_loss',
    learning_rate=0.05,
    max_iter=50,
    max_leaf_nodes=15,
    random_state=42
)
model.fit(X_train, y_train)

# Evaluate model accuracy
preds_prob = model.predict_proba(X_test)[:, 1]
print(f"[+] Model Trained Successfully! Accuracy (ROC-AUC): {roc_auc_score(y_test, preds_prob):.4f}")

# Save the trained model file to disk
joblib.dump(model, "edge_detector.txt")
print("[+] Model saved locally as 'edge_detector.txt' (< 50 KB)")

# 4. Real-time Anomaly Scoring Function (s_t calculation)
def calculate_anomaly_score(traffic_vector: dict, threshold: float = 0.70) -> dict:
    """
    Evaluates incoming packet features and computes the anomaly score s_t.
    """
    input_df = pd.DataFrame([traffic_vector])
    
    # Compute probability that the current traffic is an attack: s_t in [0, 1]
    s_t = float(model.predict_proba(input_df)[0][1])
    
    # Trigger gate: Wake the multi-agent swarm only if s_t >= 0.70
    alert_triggered = s_t >= threshold
    
    return {
        "s_t": round(s_t, 4),
        "alert_triggered": alert_triggered,
        "metrics": traffic_vector
    }

# 5. Test Live Traffic Evaluation
print("\n" + "-" * 40)
print("  LIVE TRAFFIC EVALUATION TEST")
print("-" * 40)

# Test Case 1: Clean Normal Traffic
clean_traffic = {
    'packets_per_sec': 145.0,
    'syn_flag_ratio': 0.03,
    'avg_packet_size': 510.0,
    'flow_duration': 4.8
}
result_clean = calculate_anomaly_score(clean_traffic)
print(f"[*] Clean Flow  -> s_t: {result_clean['s_t']} | Wake Agents? -> {result_clean['alert_triggered']}")

# Test Case 2: Malicious SYN Flood Attack
attack_traffic = {
    'packets_per_sec': 7900.0,
    'syn_flag_ratio': 0.96,
    'avg_packet_size': 64.0,
    'flow_duration': 0.12
}
result_attack = calculate_anomaly_score(attack_traffic)
print(f"[!] Attack Flow -> s_t: {result_attack['s_t']} | Wake Agents? -> {result_attack['alert_triggered']}")
print("=" * 60)
