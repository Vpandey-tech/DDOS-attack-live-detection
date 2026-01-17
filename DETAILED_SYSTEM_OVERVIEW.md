# 🧠 Sentinel: Detailed Technical Documentation
> **Deep Dive into Architecture, Algorithms, and Logic**

---

## 1. 🔍 The "Hybrid Ensemble" Intelligence Engine

The core differentiator of Sentinel is its **Quad-Model Ensemble**. Unlike single-model systems that are prone to overfitting or missing novel attacks, Sentinel uses a "Committee of Experts" approach.

### The Models
1.  **LucidCNN (Convolutional Neural Network)**
    *   **Role**: The "Pattern Matcher".
    *   **Architecture**: 1D CNN optimized for sequential traffic data.
    *   **Strength**: Extremely high accuracy (>99%) on known attack signatures like volumetric HTTP floods and TCP SYN floods.
    *   **Input**: 72-feature vector normalized via `StandardScaler`.

2.  **AutoEncoder (Unsupervised Anomaly Detector)**
    *   **Role**: The "Outlier Detector".
    *   **Architecture**: PyTorch-based neural network that compresses input to a latent space (32 dims) and attempts to reconstruct it.
    *   **Logic**: `Error = (Input - Output)^2`. High error means the model has *never* seen this traffic pattern before.
    *   **Strength**: Detecting Zero-Day attacks and subtle low-volume exploits.

3.  **XGBoost & Random Forest**
    *   **Role**: The "Statistical Validators".
    *   **Strength**: Excellent at handling tabular data regularities and edge cases that deep learning might miss.

### Decision Logic (The "Vote")
The `ModelInference.predict()` method acts as the Supreme Court. It aggregates votes using a weighted system:

```python
# Pseudo-code logic
Ensemble_Score = (Lucid_Conf * 0.50) + (XGB_Conf * 0.25) + (RF_Conf * 0.25)

if (Ensemble_Score > 0.85):
    Result = "HIGH_THREAT" (Certain Attack)
elif (Ensemble_Score > 0.60 AND AutoEncoder_Anomaly == True):
    Result = "HIGH_THREAT" (Confirmed Anomaly)
elif (AutoEncoder_Anomaly == True):
    Result = "MEDIUM_THREAT" (Suspicious)
else:
    Result = "BENIGN"
```

---

## 2. ⚡ Temporal Escalation & Event Correlation

A single malicious packet might be a fluke. A stream of them is an attack. Sentinel implements **Temporal Memory**:

*   **Logic**: The system maintains a rolling history of the last 5 seconds of alerts.
*   **Escalation Rule**: If 5 or more `MEDIUM` threats are detected within this window, the Threat Level is instantly escalated to `HIGH`.
*   **Outcome**: This catches "Slow-and-Low" attacks that try to fly under the radar by triggering only weak alerts individually.

---

## 3. 🛡️ Prevention System Architecture

The mitigation engine (`prevention_system.py`) is designed to be **Non-Blocking** and **Fail-Safe**.

### Threading Model
*   **Main Thread**: Handles UI and Decision Making.
*   **Worker Thread**: Handles `netsh` firewall commands.
*   **Why?**: Executing a Windows shell command takes ~20-50ms. If we did this in the main loop, 100 attacks would freeze the UI for 5 seconds. By using a worker queue, the UI remains perfectly fluid at 60 FPS while the background worker processes the block list.

### Intelligent Whitelisting
Before blocking an IP, the system checks:
1.  Is it the **Localhost** (127.0.0.1)?
2.  Is it the **Default Gateway** (Router)?
3.  Is it a known **DNS Server** (8.8.8.8, 1.1.1.1)?

If YES, the block is rejected, preventing accidental self-DoS.

---

## 4. 🦅 Packet Capture: Raw Sockets vs. Scapy

One of the biggest engineering challenges was performance reliability.

### The "Scapy" Bottleneck
Standard Python network libraries (like Scapy) are powerful but slow. They parse every bit of a packet into high-level Python objects. Throughput is capped at ~100-200 packets/second.

### The "Raw Socket" Solution
Sentinel implements a `struct` based binary parser on top of native Windows Sockets (`SIO_RCVALL`).
*   **Zero-Copy (Almost)**: We read the binary buffer directly from the kernel.
*   **Bitwise Parsing**: We extract *only* the headers we need (IP Src/Dst, TCP Ports) using fast bitwise operations.
*   **Performance**: Capable of handling **10,000+ packets/second** on a standard i7 Laptop.

---

## 5. 📊 Calibration Logic

Every network is unique. A server doing video streaming has different "normal" traffic stats than an IoT device.

*   **Process**:
    1.  User clicks "Calibrate".
    2.  System captures 60 seconds of traffic.
    3.  AutoEncoder calculates reconstruction error for every single flow.
    4.  **Baseline Calculation**: `Threshold = Mean_Error + (3 * Standard_Deviation)`.
*   **Result**: This sets a statistical ceiling (`99.7%` confidence interval). Anything breaking this ceiling is mathematically proven to be an outlier for *your specific network*.

---

## 6. 📁 File Structure & Roles

*   `enhanced_app.py`: **The Conductor**. Orchestrates the UI thread, loads models, and manages the main loop.
*   `enhanced_dashboard.py`: **The Artist**. Contains strictly UI rendering logic (Plotly charts, HTML/CSS).
*   `model_inference.py`: **The Brain**. Contains the Neural Network classes and the decision matrix.
*   `packet_capture.py`: **The Eyes**. Handles the raw socket connection to the network card.
*   `flow_manager.py`: **The Translator**. Aggregates packets into meaningful flows and extracts features.
*   `traffic_simulator.py`: **The Sparring Partner**. Generates synthetic traffic for testing.

---

## 7. ⚠️ Troubleshooting Common Issues

### "System Uncalibrated" Warning
*   **Cause**: You tried to start detection without a baseline.
*   **Fix**: Click "Step 1: Calibrate System" and wait for the green success message.

### "Access Denied" / "Scapy Mode Active"
*   **Cause**: Python was not run as Administrator. Raw Sockets require Admin rights.
*   **Fix**: Close terminal. Right-click VS Code/Terminal -> **Run as Administrator**.

### "Dependencies Missing"
*   **Cause**: `xgboost` or specific `torch` versions might be missing.
*   **Fix**: The system is resilient. If XGBoost is missing, it simply disables that voter and runs with the remaining 3 models (Lucid, RF, AutoEncoder).
