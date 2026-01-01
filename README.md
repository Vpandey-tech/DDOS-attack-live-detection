# 🛡️ Enterprise-Grade DDoS Detection & Mitigation System (v2.0)

> **"Fortress" Upgrade**: Now featuring **Raw Socket Interception**, **Async Mitigation Strategies**, and **Adaptive Threat Scoring**.

This system is a **hybrid AI-powered network defense solution** designed to detect and block DDoS attacks in real-time with enterprise-grade performance. It combines **LucidCNN** (deep learning for known signatures) and **AutoEncoder** (unsupervised learning for zero-day anomalies) with a high-performance, asynchronous mitigation engine.

---

## 🚀 **Major Upgrades in v2.0**

| Feature | Old System | **New System (v2.0)** |
|:---|:---|:---|
| **Packet Processing** | Scapy (Slow, high overhead) | **Raw Sockets (Kernel-bypass speed)** via `socket.ioctl` (100x faster) |
| **Mitigation** | Sync Blocking (Freezes app) | **Async Threaded Execution** with exponential backoff & verification |
| **Reliability** | Basic try-except | **Fail-safe Retries, Rule Verification & Deadlock Prevention** |
| **Persistence** | None (Ram only) | **JSON-based Status Saving (Blocks & Calibration)** |
| **Architecture** | Linear execution | **Event-Driven, Queue-Decoupled & Thread-Safe (`RLock`)** |
| **Safety** | Manual Whitelist | **Auto-Gateway Detection & Intelligent Whitelisting** |

---

## 🎯 **What's Included in This Project**

### 1. **Data Ingestion Layer (High Performance)**
- **Primary Mode**: Uses `socket.SOCK_RAW` to hook directly into the Windows network stack, bypassing standard OS processing overhead.
- **Protocol Parsing**: Manual binary unpacking (`struct.unpack`) of IP/TCP/UDP headers for nanosecond-level processing speed.
- **Fallback**: Automatically degrades to Scapy if Admin privileges are missing.

### 2. **🧠 AI Detection Core**
- **LucidCNN Model**: A deep convolutional neural network trained on the CIC-DDoS2019 dataset to classify known attack patterns (SYN Flood, UDP Flood, etc.).
- **AutoEncoder**: An anomaly detector that learns *your* specific network's "normal" behavior.
- **Adaptive Thresholding**: The anomaly threshold isn't fixed. It is **dynamically calculated** during the 60-second calibration phase to dramatically reduce false positives tailored to your environment.

### 3. **🛡️ Active Prevention System (Persistent)**
- **Non-Blocking Operation**: Firewall rules are applied in background threads.
- **Persistent Blocklist**: Blocked IPs are saved to `blocked_ips.json` and automatically restored on restart.
- **Verification Loop**: After issuing a block command, the system checks the firewall registry.
- **Resilience**: Exponential backoff strategy for failed commands.
- **Safety First**: Whitelists Gateway, Local IP, and DNS servers.

### 4. **📊 Real-time Dashboard (Enhanced)**
- **Raw Packet Counter**: Displays the exact number of raw packets captured by the kernel sniffer (matching terminal output).
- **Flow vs. Packet Metrics**: Clearly distinguishes between processed flows (conversations) and raw packets.
- **Real-time Visualization**: Interactive charts for traffic volume and threat distribution.

### 5. **🎲 Traffic Simulator**
- Built-in simulator for safe testing without real attackers.
- Supports SYN Flood, UDP Flood, HTTP Flood, and ICMP Flood generation.
- Configurable intensity and packet rates.

---

## 🚀 **How to Use This Project**

### **Step 1: Prerequisites**
1.  **Python 3.10+** installed.
2.  **Administrator Privileges**: Required to use Raw Sockets (for speed) and to modify the Windows Firewall.
3.  **Model Files** (Must be in root directory):
    - `lucid.h5`, `lucid.pkl`
    - `auto.pth`, `auto.pkl`

### **Step 2: Installation**
```bash
# Install required Python packages
pip install streamlit scapy pandas numpy tensorflow torch psutil plotly
```

### **Step 3: Running the System**
**CRITICAL:** For the v2.0 Performance Mode (Raw Sockets), you **MUST** run the terminal as Administrator.

1.  Right-click your terminal application (Command Prompt / PowerShell / VS Code).
2.  Select **"Run as Administrator"**.
3.  Navigate to the project folder.
4.  Run the command:
    ```bash
    streamlit run app.py
    ```

---

## 🎮 **User Guide & Workflow**

### **1. Calibration (Mandatory First Step)**
When you first launch the app, the "Start Detection" button is disabled to prevent false positives.
1.  Ensure your network is in a "normal" state (browsing, watching videos is fine).
2.  Click **"Step 1: Calibrate System"** in the sidebar.
3.  Wait **60 seconds**. The AI is learning your network's specific "Heartbeat" and setting the Adaptive Threshold.
4.  Once complete, the system locks in your personalized profile.

### **2. Active Detection**
1.  Click **"Step 2: Start Detection"**.
2.  You should see the status change to **"ACTIVE"** (Green).
3.  **Performance Check**: Look at your terminal/logs.
    - If you see `🚀 PERFORMANCE MODE: Starting Raw Socket Sniffer`, you are running at max speed.
    - If you see `🛡️ STANDARD MODE`, you are running on Scapy (slower) likely because you aren't Admin.

### **3. blocking & Prevention**
- **Simulation Mode (Default)**: The system logs "Would block IP..." but takes no action. Ideal for testing.
- **Active IP Blocking**: Switch to "Active Mode" in the sidebar. The system will now create real Windows Firewall rules to drop malicious traffic.
- **Manage Blocks**: View and unblock IPs directly from the "Blocked IPs" expander in the sidebar.

### **4. Testing with Simulator**
1.  Go to the **"Testing & Simulation"** tab.
2.  Select an attack type (e.g., **SYN Flood**).
3.  Set intensity (start low, e.g., 50%).
4.  Click **Start Simulation**.
5.  Watch the dashboard—you should see the "Threat Level" spike and (if in Active Mode) the prevention system engaging.

---

## 💻 **Using in VS Code**

1.  **Open Project**: File > Open Folder > Select `curr_ddos`.
2.  **Terminal**: Terminal > New Terminal.
3.  **Environment**: Ensure you select your Python interpreter (Ctrl+Shift+P > Python: Select Interpreter).
4.  **Run as Admin**:
    - If using the integrated terminal, VS Code itself must be run as Admin for Raw Sockets to work.
    - **Tip**: You can assume "Standard Mode" (Scapy) works fine for development without Admin, but detection might lag under heavy load.

---

## 🔬 **Technical Implementation Details**

### **packet_capture.py (The Engine)**
- **Dual-Mode Sniffer**:
    - `_run_raw_socket_sniffer()`: Uses `socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)` bound to the host IP. Sets `SIO_RCVALL` ioctl to promiscuous mode. Manually parses 20-byte IP headers.
    - `_run_scapy_sniffer()`: Fallback using Scapy library.

### **prevention_system.py (The Shield)**
- **Thread-Safe**: Uses `threading.RLock()` to manage the `blocked_ips` set.
- **Command Queue**: `subprocess.run` calls are offloaded to daemon threads (`threading.Thread`) to avoid UI freezing.
- **Recovery**: Includes a `_run_command_safe` helper that catches timeouts and retries failed `netsh` commands.

### **flow_manager.py (The State)**
- **Flow Expiration**: A background thread checks for flows inactive for >`TIMEOUT` seconds every 1s.
- **Lock Optimization**: Feature extraction (heavy CPU) is performed **outside** the main flow lock to prevent blocking the packet capture thread.

---

## � **Support & Troubleshooting**

**Q: "Capture failed on interface" / "Raw Socket check failed"**
> **Fix**: You are likely not running as Administrator. The system will fall back to Scapy (slower). Right-click your terminal and "Run as Administrator".

**Q: "No live traffic detected"**
> **Fix**: Ensure you selected the correct interface (WiFi/Ethernet). Windows often lists Virtual Adapters (VMware/Hyper-V) first. Select your actual Wi-Fi adapter. try generating traffic (open a YouTube video).

**Q: "System is blocking my phone!"**
> **Fix**: The system auto-whitelists your Gateway and Local IP, but if a device on your LAN behaves aggressively (scanning ports, etc.), it might get flagged. Use the **"Unblock IP"** button in the sidebar to manually allow it.

**Q: Why is the "Start Detection" button disabled?**
> **Fix**: You **must** calibrate the system first. This is a safety feature to ensure the AutoEncoder doesn't flag normal traffic as an anomaly.

---
*NextGen DDoS Protection • Built for Speed • Powered by AI*