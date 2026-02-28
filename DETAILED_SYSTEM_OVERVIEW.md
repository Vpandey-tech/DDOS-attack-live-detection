# 🧠 Sentinel: Technical Documentation

> Deep Dive into Architecture, Algorithms, and Implementation Details

[![Hugging Face Spaces](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Spaces-blue)](https://huggingface.co/spaces/sanketDamre/DDOS-ATTACK-PREVENTION)

---

## 1. Hybrid Ensemble Intelligence Engine

The core of Sentinel is a **4-model weighted ensemble** that combines diverse learning paradigms for robust decision-making.

### 1.1 Model Architectures

| Model | Type | Framework | Input | Role |
|-------|------|-----------|-------|------|
| **LucidCNN** | 1D Convolutional Neural Network | TensorFlow/Keras | 72 features (StandardScaler) | Pattern matching on known attack signatures |
| **AutoEncoder** | Unsupervised Anomaly Detector | PyTorch | 72 features (MinMaxScaler) | Zero-day detection via reconstruction error |
| **XGBoost** | Gradient Boosted Trees | XGBoost | 72 features (StandardScaler) | Statistical validation, handles tabular data well |
| **Random Forest** | Bagged Decision Trees | Scikit-Learn | 72 features (StandardScaler) | Robust baseline, captures feature interactions |

### 1.2 LucidCNN Architecture
```
Input (72) → ExpandDims → Conv1D(64, k=3) → ReLU → MaxPool
          → Conv1D(128, k=3) → ReLU → MaxPool
          → Flatten → Dense(128) → Dropout(0.3) → Dense(1, Sigmoid)
```

### 1.3 AutoEncoder Architecture
```
Encoder: Linear(72→128) → ReLU → Linear(128→64) → ReLU → Linear(64→32)
Decoder: Linear(32→64)  → ReLU → Linear(64→128) → ReLU → Linear(128→72, Sigmoid)

Anomaly Score = MSE(Input, Reconstructed)
Threshold = Mean(baseline_errors) + 3 × Std(baseline_errors)
```

### 1.4 Ensemble Decision Logic

```python
# Weighted voting (normalized dynamically based on loaded models)
w_lucid, w_xgb, w_rf = 0.50, 0.25, 0.25
ensemble_score = (lucid_conf × w_lucid) + (xgb_conf × w_xgb) + (rf_conf × w_rf)

# Decision Matrix
if ensemble_score > 0.85:                           → HIGH THREAT (certain attack)
elif ensemble_score > 0.60 AND autoencoder_anomaly:  → HIGH THREAT (confirmed anomaly)
elif autoencoder_anomaly OR ensemble_score > 0.50:   → MEDIUM THREAT (suspicious)
else:                                                → BENIGN
```

---

## 2. Temporal Escalation & Event Correlation

A single malicious packet might be a fluke. A stream of them is an attack.

- **Rolling Window**: System maintains a 5-second history of all threats
- **Escalation Rule**: 5+ MEDIUM threats within the window → automatic escalation to HIGH
- **Purpose**: Catches "slow-and-low" attacks that fly under individual detection thresholds

```python
recent_mediums = count(threats in last 5 seconds where level == 'MEDIUM')
if threat_level == "MEDIUM" and recent_mediums >= 5:
    threat_level = "HIGH"
    prediction = "Attack (Escalated)"
```

---

## 3. Packet Capture Engine

### 3.1 Raw Socket Mode (Windows, Admin Required)
The high-performance capture path uses native Windows raw sockets:

```python
sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
sniffer.bind((host_ip, 0))
sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
sniffer.ioctl(SIO_RCVALL, RCVALL_ON)  # Promiscuous mode
```

**Binary parsing** extracts only the headers needed (IP src/dst, TCP/UDP ports) using `struct.unpack` — no Python object overhead. Throughput: **10,000+ packets/second**.

### 3.2 Scapy Fallback
If raw sockets fail (no admin privileges), the system falls back to Scapy's `sniff()` function. Performance is lower (~200 pkt/s) but works without special privileges on Linux.

### 3.3 Capture Method Selection
```
Windows + Admin → Raw Socket (Performance Mode)
Windows - Admin → Scapy (Standard Mode)  
Linux           → Scapy (Standard Mode, uses PF_PACKET natively)
```

---

## 4. Flow Assembly & Feature Extraction

### 4.1 Flow Manager (`flow_manager.py`)
Packets are grouped into **5-tuple flows**: `(src_ip, dst_ip, src_port, dst_port, protocol)`.

- Flows are expired after a configurable timeout (default: 10 seconds)
- Upon expiration, the flow is sent to the Feature Extractor

### 4.2 Feature Extractor (`feature_extractor.py`)
Extracts **72 statistical features** per flow, matching the CICFlowMeter standard:

| Feature Group | Count | Examples |
|---------------|-------|---------|
| Packet length stats | 16 | Max, Min, Mean, Std for fwd/bwd packets |
| Flow duration & rates | 8 | Duration, bytes/sec, packets/sec |
| Inter-arrival times | 8 | IAT mean, std, max, min (fwd/bwd) |
| TCP flags | 8 | SYN, ACK, FIN, PSH, URG, RST counts |
| Subflow statistics | 8 | Subflow fwd/bwd packets and bytes |
| Window sizes | 4 | Init window bytes forward/backward |
| Active/Idle times | 8 | Active/Idle mean, std, max, min |
| Bulk transfer stats | 6 | Avg bytes/bulk, avg packets/bulk |
| Other | 6 | Down/Up ratio, avg packet size, segment sizes |

---

## 5. Prevention System (`prevention_system.py`)

### 5.1 Non-Blocking Architecture
- **Main Thread**: Handles UI and decision-making
- **Worker Thread**: Executes `netsh advfirewall` commands asynchronously
- **Why?**: Each `netsh` call takes ~20-50ms. Synchronous execution of 100 blocks would freeze the UI for 5 seconds.

### 5.2 Firewall Commands
```bash
# Block an IP
netsh advfirewall firewall add rule name="SENTINEL_BLOCK_{ip}" dir=in action=block remoteip={ip}

# Unblock an IP
netsh advfirewall firewall delete rule name="SENTINEL_BLOCK_{ip}"
```

### 5.3 Intelligent Whitelisting
Before blocking, the system checks:
1. Is it **localhost** (127.0.0.1)?
2. Is it the **default gateway** (router)?
3. Is it a known **DNS server** (8.8.8.8, 1.1.1.1)?
4. Is it a **private network** address (192.168.x.x, 10.x.x.x)?

If YES → block is rejected to prevent self-DoS.

---

## 6. Calibration System

Every network has unique "normal" traffic patterns. Calibration learns yours.

### Process
1. User clicks "Calibrate" → 60-second capture begins
2. Only the AutoEncoder runs during calibration (no classification)
3. Reconstruction errors are collected for all captured flows
4. **Threshold = Mean(errors) + 3 × Std(errors)** — covers 99.7% confidence interval
5. Threshold is saved to `baseline.pkl` for persistence across sessions

### Continuous Learning
During normal operation, if a flow is classified as BENIGN with high confidence (ensemble_score < 0.2), its AutoEncoder error is added to the baseline. Every 100 new samples, the threshold is recalculated.

---

## 7. Dashboard UI (`enhanced_dashboard.py`)

### Design Principles
- **Minimalist Light Theme** — Clean white cards, Inter font, subtle shadows
- **Persistent Data Table** — Uses `st.dataframe` (fixed 300px height) instead of HTML divs to prevent scroll jumping
- **Real-Time Charts** — Plotly with 10-second interval aggregation, transparent backgrounds
- **Responsive Layout** — 12:5 column ratio (main feed : side alerts)

### KPI Cards
| Card | Metric | Source |
|------|--------|--------|
| Total Packets Analyzed | Cumulative flow count | `len(detection_results)` |
| Threats Detected | Attack count | Filtered by `'Attack' in prediction` |
| Current Attack Rate | % of last 100 flows that are attacks | Rolling window |
| Inference Latency | Average model response time | Per-flow timing |

---

## 8. Traffic Simulator (`traffic_simulator.py`)

Built-in traffic generator for safe testing without affecting real networks.

### Supported Attack Types
| Type | Protocol | Characteristics |
|------|----------|----------------|
| **SYN Flood** | TCP (6) | High packet rate, small packets (60 bytes), random source IPs |
| **UDP Flood** | UDP (17) | Large packets, high bandwidth, random ports |
| **HTTP Flood** | TCP (6) | Port 80/443 targeted, medium packet sizes |
| **ICMP Flood** | ICMP (1) | Ping flood, uniform packet sizes |
| **Normal Traffic** | Mixed | Realistic browsing patterns, low rates |

### Configuration
- **Intensity**: 0.0 (light) → 1.0 (extreme)
- **Packet Rate**: 1–50 packets/second
- **Attack/Benign Mix**: Automatically varies based on intensity

---

## 9. File Interconnection Map

```
enhanced_app.py (Main Orchestrator)
    ├── imports → enhanced_dashboard.py (UI rendering)
    ├── imports → model_inference.py (AI predictions)
    ├── imports → packet_capture.py (network capture)
    ├── imports → flow_manager.py (packet → flow assembly)
    │                └── imports → feature_extractor.py (72 features)
    ├── imports → traffic_simulator.py (synthetic traffic)
    ├── imports → prevention_system.py (firewall blocking)
    └── imports → utils.py (helpers)

model_inference.py
    ├── loads → lucid.h5 + lucid.pkl (LucidCNN + StandardScaler)
    ├── loads → auto.pth + auto.pkl (AutoEncoder + MinMaxScaler)
    ├── loads → xgboost_ddos.pkl (XGBoost)
    └── loads → random_forest_ddos.pkl (Random Forest)
```

---

## 10. Deployment Notes

### Hugging Face Spaces
- Uses `Dockerfile` with Python 3.9-slim base
- Installs `libpcap-dev` for Scapy compatibility
- Runs on port 7860 (HF default)
- Traffic Simulator works; live capture limited to container network

### GitHub → Hugging Face Sync
Pushing to GitHub does **NOT** auto-deploy to HF Spaces. They are separate Git repositories. Options:
1. **Manual**: Push to both repos separately
2. **GitHub Action**: Set up a workflow to sync commits to HF Space repo
3. **HF CLI**: `huggingface-cli upload` from your local machine

---

## 11. Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| "System Uncalibrated" | No baseline learned | Click "Start Calibration (60s)" |
| "Access Denied" / Scapy fallback | Not running as Admin | Right-click terminal → Run as Administrator |
| "Model file missing" | `.h5`/`.pkl`/`.pth` not in root | Ensure all 6 model files are present |
| XGBoost warning | Version mismatch | System runs fine with 3 models if XGB fails |
| Scroll jumping | Old UI issue | Fixed: using `st.dataframe` with fixed height |
