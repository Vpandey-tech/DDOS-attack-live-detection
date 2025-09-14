
# 🛡️ Advanced DDoS Detection System

## Complete Guide & Documentation

### Overview

This is a **state-of-the-art, real-time DDoS detection system** that uses artificial intelligence to monitor network traffic and identify potential attacks with extremely low latency. The system combines **LucidCNN** (a deep learning classifier) and an **AutoEncoder** (anomaly detection) with a unique **Adaptive Thresholding** engine for hybrid threat detection.

---

## 🎯 **What's Included in This Project**

### **Core Components:**

1.  **🧠 AI Detection Engine**
    -   **LucidCNN Model**: Binary classifier for Attack/Benign prediction.
    -   **AutoEncoder Model**: Anomaly detection trained on benign traffic.
    -   **Adaptive Thresholding**: The AutoEncoder's anomaly threshold isn't fixed. It intelligently learns your network's "normal" behavior during a calibration phase to dramatically reduce false positives.
    -   **Hybrid Logic**: If either model flags traffic as an attack, it's considered a threat.

2.  **📊 Real-time Dashboard**
    -   Professional web interface with live updates.
    -   Interactive charts and visualizations.
    -   Real-time threat alerts with color coding.
    -   Performance metrics and analytics.

3.  **🌐 Network Traffic Analysis**
    -   Live packet capture from network interfaces with auto-detection.
    -   Flow assembly using 5-tuple (src IP, dst IP, src port, dst port, protocol).
    -   72-feature extraction engine optimized for speed.
    -   Automatic flow timeout and processing.

4.  **🎲 Traffic Simulator**
    -   Built-in simulator for testing the system.
    -   Multiple attack types: SYN Flood, UDP Flood, HTTP Flood, ICMP Flood.
    -   Configurable attack intensity and packet rates.
    -   Realistic network traffic generation.

5.  **⚡ High Performance**
    -   Multi-threaded architecture for concurrent processing.
    -   Queue-based communication for thread safety.
    -   Optimized feature extraction (72 features in milliseconds).
    -   Real-time processing with minimal latency.

---

## 🚀 **How to Use This Project**

### **Step 1: Prerequisites**

1.  **Upload Your Model Files** (You've already done this ✅)
    -   `lucid.h5` - Your LucidCNN TensorFlow model
    -   `lucid.pkl` - StandardScaler for LucidCNN
    -   `auto.pth` - Your AutoEncoder PyTorch model
    -   `auto.pkl` - MinMaxScaler for AutoEncoder

2.  **System Requirements**
    -   Python 3.11+
    -   Network interface access (run with admin/sudo privileges if needed).
    -   Sufficient RAM for real-time processing.

### **Step 2: Running the System**

```bash
streamlit run app.py
````

The application will open in your web browser.

### **Step 3: Using the Interface**

#### **🛡️ Control Center (Sidebar)**

**System Status:**

  - 🟡 Uncalibrated = System needs to learn your network first.
  - 🟢 Calibrated & Ready = System is ready for detection.
  - 🟢 ACTIVE / 🔴 STOPPED = Shows if detection is currently running.

**Network Configuration:**

  - Select interface: The system auto-detects the best interface (e.g., Wi-Fi, Ethernet).
  - Flow timeout: 5-30 seconds (time before processing inactive flows).

**Real Traffic Detection (New 2-Step Process):**

1.  **Step 1: Calibrate System**: **You must do this first.** Click this button to start a 60-second scan of your normal network traffic. The AI uses this to build a personalized baseline.
2.  **Step 2: Start Detection**: After calibration is complete, this button will be enabled. Click it to begin monitoring live network traffic for threats.
3.  **Stop Detection**: Stops the live monitoring.

**Traffic Simulator:**

  - Attack Type: Choose from Normal, SYN Flood, UDP Flood, etc.
  - Attack Intensity: 0% = normal traffic, 100% = full attack.
  - Packet Rate: How many flows/second to generate.
  - Start/Stop Simulator buttons.

### **Step 4: Understanding the Dashboard**

#### **📊 Main Dashboard Features:**

1.  **System Status Banner**

      - Shows if detection is active.
      - Displays simulation status and settings.

2.  **Performance Metrics**

      - Total Flows: Number of network flows processed.
      - Threats Detected: Number of attacks identified.
      - **Adaptive Threshold**: Displays the current, live threshold the AutoEncoder is using. This value is unique to your network\!

3.  **🚨 Live Threat Intelligence**

      - Real-time alerts for high and medium severity threats.
      - Color-coded alerts (Red = High, Orange = Medium).
      - Shows source/target IPs, ports, and confidence scores.

4.  **📈 Advanced Analytics**

      - Real-time timeline of traffic and attacks.
      - Threat distribution pie chart.
      - Attack pattern analysis by protocol.

5.  **🔍 Live Detection Feed**

      - Real-time stream of all detections.
      - Shows packet details, predictions, and confidence scores.
      - Color-coded based on threat level.

-----

## 🎯 **Testing the System**

### **Method 1: Traffic Simulator (Recommended)**

1.  **Start the Simulator:**

      - Go to sidebar → 'Testing & Simulation' tab.
      - Select attack type (e.g., "SYN Flood").
      - Set intensity to 0.8 (80% attack traffic).
      - Set packet rate to 25 packets/second.
      - Click "Start Simulator".

2.  **Observe Results:**

      - Watch the dashboard update in real-time.
      - See threat alerts appear.
      - Monitor charts and analytics.

### **Method 2: Real Network Traffic (New Workflow)**

1.  **Calibrate the System:**

      - Ensure your network usage is "normal" (e.g., just browsing, no heavy downloads).
      - In the sidebar, click **"Step 1: Calibrate System"**.
      - Wait for the 60-second process to complete. A success message will appear.

2.  **Start Detection:**

      - The **"Step 2: Start Detection"** button is now enabled. Click it.
      - The system will now monitor your live traffic using the personalized threshold it just learned.

-----

## 🏆 **Advantages & Features**

### **🚀 Performance Advantages:**

1.  **Adaptive Learning**

      - The system calibrates itself on your specific network's traffic, creating a personalized and highly accurate detection baseline. This is a key feature for preventing false alarms.

2.  **Ultra-Low Latency**

      - Feature extraction in milliseconds.
      - Real-time processing without delays.
      - Optimized multi-threading.

3.  **High Accuracy**

      - Hybrid AI approach (LucidCNN + AutoEncoder).
      - Trained on your specific data.
      - Dramatically reduced false positives thanks to the calibration step.

### **💡 Technical Features:**

1.  **72-Feature Analysis**

      - Comprehensive statistical analysis of traffic flows.

2.  **Professional UI**

      - Modern, responsive design with real-time updates.

3.  **Comprehensive Monitoring**

      - Live threat feed, performance metrics, and attack pattern analysis.

-----

## 💻 **Using in VS Code**

### **Step 1: Download the Code**

1.  Download the project files as a ZIP.
2.  Extract the files to your computer.

### **Step 2: Setup in VS Code**

1.  Open the extracted folder in VS Code.
2.  Install the Python extension.

### **Step 3: Install Dependencies**

```bash
# In VS Code terminal
pip install streamlit pandas plotly numpy scikit-learn tensorflow torch scapy psutil
```

### **Step 4: Run the System**

```bash
# In VS Code terminal
streamlit run app.py
```

-----

## 🔬 **Technical Implementation Details**

### **AI Models Integration:**

**LucidCNN (Primary Classifier):**

  - Framework: TensorFlow/Keras
  - Purpose: Identifies known attack patterns. Its threshold is fixed.

**AutoEncoder (Anomaly Detector):**

  - Framework: PyTorch
  - Logic: A high reconstruction error suggests an anomaly. The threshold for what is considered "high" is not fixed; it is **dynamically calculated** during the 60-second calibration phase.

**Hybrid Decision:**

  - Final prediction = Attack if (LucidCNN confidence \> 0.5 OR AutoEncoder error \> **Adaptive Threshold**)
  - Threat level = HIGH if both models agree, MEDIUM if only one flags it.

-----

## 📞 **Support & Troubleshooting**

### **Common Issues:**

**Q: Why is the "Start Detection" button disabled?**
A: You **must** calibrate the system first. Click the **"Step 1: Calibrate System"** button in the sidebar and wait 60 seconds. This is required for the adaptive AI to learn your network's normal behavior.

**Q: Models not loading?**
A: Ensure all 4 model files are in the root directory with the correct names (`lucid.h5`, `lucid.pkl`, `auto.pth`, `auto.pkl`).

**Q: Permission errors or No Interfaces Found?**
A: The script may need administrator/sudo privileges to capture network packets.

-----

## 🎊 **Conclusion**

You now have a **world-class DDoS detection system** with:

✅ **Adaptive AI-powered threat detection** with your trained models.
✅ **Professional real-time dashboard** with advanced analytics.
✅ **Built-in traffic simulator** for comprehensive testing.
✅ **A mandatory calibration step** for personalized, high-accuracy detection.

The system is **ready to use immediately** and can detect both simulated and real network attacks with high accuracy\!

-----

*🛡️ **Your Advanced DDoS Detection System is ready for action\!** 🛡️*

```
```