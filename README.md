# 🛡️ Sentinel: Advanced Hybrid AI DDoS Defense System
> **Enterprise-Grade Real-Time Network Protection** | *Version 2.0 "Fortress"*

![License](https://img.shields.io/badge/License-MIT-blue.svg) ![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![Status](https://img.shields.io/badge/Status-Production%20Ready-green) ![AI](https://img.shields.io/badge/AI-Ensemble%20(CNN%2BAutoEncoder%2BXGB%2BRF)-purple)

---

## 📖 Introduction
**Sentinel** is a state-of-the-art DDoS detection and mitigation system designed for modern network environments. Unlike traditional firewalls that rely on static rules or simple rate limiting, Sentinel employs a **Hybrid AI Ensemble** to inspect traffic behavior in real-time.

By combining Deep Learning (**LucidCNN**), Anomaly Detection (**AutoEncoder**), and Machine Learning classifiers (**XGBoost, Random Forest**), the system can identify both known attack patterns (SYN Flood, UDP Flood) and unknown "Zero-Day" anomalies with exceptionally low false positives.

---

## ✨ Key Features
*   **🧠 Quad-Core AI Engine**: Uses a weighted ensemble of 4 distinct models for robust decision making.
*   **⚡ Kernel-Level Capture**: Features a customized **Raw Socket** engine implementation for high-speed packet ingestion (10,000+ packets/sec) on Windows, bypassing standard Python slowness.
*   **🛡️ Active Mitigation**: Automatically configures Windows Firewall (`netsh`) to block malicious IPs in milliseconds.
*   **🌡️ Self-Calibrating**: Learns your specific network's "normal" baseline during a 60-second calibration phase to minimize false alarms.
*   **👁️ Real-Time Dashboard**: A high-performance Streamlit UI with <1s latency, visualizing traffic flows, threats, and model confidence instantly.
*   **👻 Simulation Mode**: Test the system safely with a built-in traffic generator that mimics various attack vectors (SYN, UDP, HTTP Floods).

---

## 🏗️ System Architecture
The system operates on a high-concurrency **Producer-Consumer** architecture:

1.  **Ingestion Layer (Producer)**: A background daemon captures raw binary packets from the network interface.
2.  **Processing Layer**:
    *   **Flow Assembly**: Packets are grouped into 5-tuple flows (SrcIP, DstIP, SrcPort, DstPort, Proto).
    *   **Feature Extraction**: 72 statistical features (std dev of packet size, inter-arrival times, etc.) are calculated per flow.
3.  **Intelligence Layer (The Brain)**:
    *   **Deep Learning**: LucidCNN scans for spatial traffic patterns.
    *   **Anomaly Detection**: AutoEncoder compares flow reconstruction error against dynamic thresholds.
    *   **Voting Mechanism**: A weighted algorithm decides the threat level (`HIGH`, `MEDIUM`, `LOW`).
4.  **Action Layer (Consumer)**:
    *   **Mitigation**: Blocking orders are sent asynchronously to the Firewall.
    *   **Visualization**: The main UI thread renders the dashboard based on the latest queue data.

---

## 🚀 Quick Start Guide

### Prerequisites
*   Windows 10/11 (Required for Raw Sockets & Firewall control).
*   Python 3.9+.
*   Administrator Privileges.

### Installation
1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/Vpandey-tech/DDOS-attack-live-detection.git
    cd ddos-sentinel
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *(Ensure you have PyTorch and TensorFlow installed compatible with your hardware)*.

3.  **Run the System**:
    **CRITICAL**: You must run the terminal as **ADMINISTRATOR**.
    ```bash
    streamlit run enhanced_app.py
    ```

### Usage Steps
1.  **Calibration**: Click **"Step 1: Calibrate System"** in the sidebar. Wait 60 seconds for the AI to learn your network baseline.
2.  **Activation**: Click **"Step 2: Start Detection"**. The system is now live.
3.  **Simulation (Optional)**: Open the "Testing & Simulation" tab to launch fake attacks and watch the system defend itself.

---

## 🛠️ Technology Stack
*   **Frontend**: Streamlit, Plotly (Reactive Data Visualization).
*   **Backend**: Python, Threading, Queues.
*   **Networking**: Raw Sockets (`socket`), Scapy (Fallback).
*   **Machine Learning**:
    *   **TensorFlow/Keras**: LucidCNN.
    *   **PyTorch**: AutoEncoder.
    *   **Scikit-Learn/XGBoost**: Random Forest & Gradient Boosting.

---

## 🔒 Security & Privacy
*   **No Data Exfiltration**: All traffic analysis is performed locally on your machine. No data is sent to the cloud.
*   **Intelligent Whitelisting**: The system automatically detects and whitelists your Gateway, Localhost, and DNS servers to prevent self-lockout.
*   **Safe Failover**: If the app crashes, it attempts to release resources gracefully.

---

## ⚠️ Disclaimer
This software is for **Educational and Defensive purposes only**. 
*   Do not use the Traffic Simulator on networks you do not own or have permission to test.
*   The authors are not responsible for any network interruption caused by the Prevention System. Always test in **Simulation Mode** first.

---

## 📄 License
MIT License. See `LICENSE` file for details.
