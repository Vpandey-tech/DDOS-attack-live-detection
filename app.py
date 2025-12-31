# import streamlit as st
# import threading
# import time
# import queue
# from dashboard import DDOSDetectionDashboard
# from traffic_simulator import TrafficSimulator
# from packet_capture import PacketCapture
# from flow_manager import FlowManager
# from model_inference import ModelInference
# import os
# import sys

# # Configure Streamlit page with enhanced settings
# st.set_page_config(
#     page_title="Advanced DDoS Detection System",
#     page_icon="🛡️",
#     layout="wide",
#     initial_sidebar_state="expanded",
# )

# def main():
#     # Initialize session state for all components. This runs only once.
#     if 'system_running' not in st.session_state:
#         st.session_state.system_running = False
#         st.session_state.flow_queue = queue.Queue(maxsize=1000)
#         st.session_state.detection_results = []
#         st.session_state.flow_manager = None
#         st.session_state.packet_capture = None
#         st.session_state.model_inference = None
#         st.session_state.traffic_simulator = TrafficSimulator()
#         st.session_state.simulation_running = False

#     # --- Pre-flight Check: Ensure Model Files Exist ---
#     required_files = ['lucid.h5', 'lucid.pkl', 'auto.pth', 'auto.pkl']
#     missing_files = [f for f in required_files if not os.path.exists(f)]
    
#     if missing_files:
#         st.error(f"❌ Missing required model files: {', '.join(missing_files)}")
#         st.info("Please upload the required model files to the project's root directory.")
#         st.stop()

#     # --- Initialize Core Components (Models) ---
#     if st.session_state.model_inference is None:
#         try:
#             with st.spinner("Loading AI models... This may take a moment."):
#                 st.session_state.model_inference = ModelInference()
#             st.success("✅ AI Models loaded successfully!")
#         except Exception as e:
#             st.error(f"❌ Failed to load models: {str(e)}")
#             st.stop()

#     # --- Render the UI ---
#     render_enhanced_sidebar()
#     dashboard = DDOSDetectionDashboard()
    
#     tab1, tab2, tab3 = st.tabs(["🔍 Live Traffic Monitoring", "🧪 Testing & Simulation", "📚 Documentation & Guide"])
    
#     with tab1:
#         dashboard.render_live_monitoring(st.session_state.detection_results, st.session_state.system_running)
    
#     with tab2:
#         simulation_stats = st.session_state.traffic_simulator.get_simulation_stats()
#         simulation_results = getattr(st.session_state.traffic_simulator, 'simulation_results', [])
#         dashboard.render_testing_simulation(simulation_results, simulation_stats)
#         render_simulation_controls()
    
#     with tab3:
#         render_documentation()
    
#     # --- Main Processing Loop ---
#     # This loop runs continuously if the system or simulator is active
#     if st.session_state.system_running or st.session_state.simulation_running:
#         process_flows()
#         # Auto-refresh the UI every 2 seconds to show new data
#         time.sleep(2)
#         st.rerun()

# def render_enhanced_sidebar():
#     """Renders the main control sidebar for the application."""
#     st.sidebar.markdown("""
#     <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
#                 padding: 1rem; border-radius: 10px; color: white; text-align: center; margin-bottom: 1rem;">
#         <h2>🛡️ Control Center</h2>
#     </div>
#     """, unsafe_allow_html=True)
    
#     st.sidebar.markdown("### 📊 System Status")
#     status_color = "🟢" if st.session_state.system_running else "🔴"
#     status_text = "ACTIVE" if st.session_state.system_running else "STOPPED"
#     st.sidebar.markdown(f"**Detection System:** {status_color} {status_text}")
    
#     sim_color = "🟢" if st.session_state.simulation_running else "🔴"
#     sim_text = "ACTIVE" if st.session_state.simulation_running else "STOPPED"
#     st.sidebar.markdown(f"**Traffic Simulator:** {sim_color} {sim_text}")
    
#     st.sidebar.markdown("---")
    
#     st.sidebar.markdown("### 🌐 Network Configuration")
#     if st.session_state.packet_capture and st.session_state.packet_capture.interface:
#         st.sidebar.info(f"📡 **Interface:** {st.session_state.packet_capture.interface}")
#         with st.expander("Show Details"):
#             st.text(st.session_state.packet_capture.get_interface_info())
#     else:
#         st.sidebar.info("🔍 Auto-detects on start")
    
#     flow_timeout = st.sidebar.slider("Flow Timeout (s)", 5, 30, 10)
    
#     st.sidebar.markdown("---")
    
#     st.sidebar.markdown("### 🎯 Real Traffic Detection")
#     col1, col2 = st.sidebar.columns(2)
#     with col1:
#         if st.button("🟢 Start Detection", disabled=st.session_state.system_running, use_container_width=True):
#             start_detection_system(flow_timeout)
#     with col2:
#         if st.button("🔴 Stop Detection", disabled=not st.session_state.system_running, use_container_width=True):
#             stop_detection_system()

#     st.sidebar.markdown("---")
    
#     st.sidebar.markdown("### 🎲 Traffic Simulator")
#     attack_types = ["Normal Traffic", "SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood"]
#     selected_attack = st.sidebar.selectbox("Attack Type", attack_types)
#     attack_intensity = st.sidebar.slider("Attack Intensity", 0.0, 1.0, 0.5, 0.1)
#     packet_rate = st.sidebar.slider("Packet Rate (pkt/s)", 1, 50, 10)
    
#     col3, col4 = st.sidebar.columns(2)
#     with col3:
#         if st.button("▶️ Start Simulator", disabled=st.session_state.simulation_running, use_container_width=True):
#             start_traffic_simulator(selected_attack, attack_intensity, packet_rate)
#     with col4:
#         if st.button("⏹️ Stop Simulator", disabled=not st.session_state.simulation_running, use_container_width=True):
#             stop_traffic_simulator()

# def start_detection_system(timeout):
#     """Initializes and starts the DDoS detection system."""
#     try:
#         with st.spinner("Initializing detection system..."):
#             st.session_state.flow_manager = FlowManager(
#                 flow_queue=st.session_state.flow_queue,
#                 timeout=timeout
#             )
#             st.session_state.packet_capture = PacketCapture(
#                 flow_manager=st.session_state.flow_manager
#             )
        
#         # CRITICAL CHECK: Verify that an interface was actually found before proceeding.
#         if not st.session_state.packet_capture.interface:
#             st.error("❌ Failed to find a valid network interface. Cannot start packet capture.")
#             st.info("💡 This is normal in cloud environments. Use the Traffic Simulator instead.")
#             return
        
#         # =================== FIX IS HERE ===================
#         #
#         # Calling the correct method: 'start_capture_thread'.
#         # This resolves the "'PacketCapture' object has no attribute 'start_capture'" error.
#         # This method starts its own background thread, so we don't need to create one here.
#         #
#         st.session_state.packet_capture.start_capture_thread()
#         # =================================================

#         st.session_state.system_running = True
#         st.success("✅ Detection system started successfully!")
#         time.sleep(1) 
#         st.rerun()
        
#     except Exception as e:
#         st.error(f"❌ Failed to start detection system: {str(e)}")
#         # Ensure the system state is correctly set to off if it fails to start
#         st.session_state.system_running = False

# def stop_detection_system():
#     """Stops the DDoS detection system."""
#     if st.session_state.packet_capture:
#         st.session_state.packet_capture.stop_capture()
#     st.session_state.system_running = False
#     st.warning("⚠️ Detection system stopped.")
#     time.sleep(1)
#     st.rerun()

# def start_traffic_simulator(attack_type, intensity, packet_rate):
#     """Starts the traffic simulator."""
#     try:
#         st.session_state.traffic_simulator.set_attack_parameters(attack_type, intensity, packet_rate)
#         st.session_state.traffic_simulator.start_simulation(st.session_state.flow_queue)
#         st.session_state.simulation_running = True
#         st.success(f"✅ Traffic simulator started: {attack_type}")
#         st.rerun()
#     except Exception as e:
#         st.error(f"❌ Failed to start traffic simulator: {str(e)}")

# def stop_traffic_simulator():
#     """Stops the traffic simulator."""
#     st.session_state.traffic_simulator.stop_simulation()
#     st.session_state.simulation_running = False
#     st.warning("⚠️ Traffic simulator stopped.")
#     st.rerun()

# def process_flows():
#     """Processes flows from the queue and updates the results."""
#     processed_count = 0
#     max_per_cycle = 20  # Process up to 20 flows per UI refresh to stay responsive
#     try:
#         while not st.session_state.flow_queue.empty() and processed_count < max_per_cycle:
#             flow_data = st.session_state.flow_queue.get_nowait()
            
#             # Get predictions from the AI models
#             result = st.session_state.model_inference.predict(flow_data['features'])
            
#             # Combine flow metadata with the prediction result
#             detection_result = {**flow_data, **result}
            
#             st.session_state.detection_results.append(detection_result)
#             # Keep the results list from growing indefinitely to save memory
#             if len(st.session_state.detection_results) > 1000:
#                 st.session_state.detection_results.pop(0)
            
#             processed_count += 1
#     except queue.Empty:
#         pass # It's normal for the queue to be empty
#     except Exception as e:
#         st.error(f"Error processing flows: {str(e)}")


# def render_simulation_controls():
#     """Render simulation control panel in the testing tab"""
#     st.markdown("### 🎮 Simulation Control Panel")
    
#     col1, col2 = st.columns(2)
    
#     with col1:
#         st.markdown("**🎯 Attack Type Selection**")
#         attack_type = st.selectbox(
#             "Choose attack type to simulate:",
#             ['SYN Flood', 'UDP Flood', 'HTTP Flood', 'ICMP Flood', 'Normal Traffic'],
#             help="Select the type of network attack to simulate for testing"
#         )
        
#         intensity = st.slider(
#             "Attack Intensity (%)",
#             min_value=10,
#             max_value=100,
#             value=50,
#             step=10,
#             help="Higher intensity = more aggressive attack simulation"
#         )
        
#         duration = st.number_input(
#             "Simulation Duration (seconds)",
#             min_value=10,
#             max_value=300,
#             value=60,
#             step=10,
#             help="How long to run the simulation"
#         )
    
#     with col2:
#         st.markdown("**🔧 Simulation Controls**")
        
#         if st.button("▶️ Start Simulation", type="primary", use_container_width=True):
#             try:
#                 st.session_state.traffic_simulator.start_simulation(
#                     attack_type=attack_type,
#                     intensity=intensity,
#                     duration=duration
#                 )
#                 st.session_state.simulation_running = True
#                 st.success(f"✅ Started {attack_type} simulation at {intensity}% intensity")
#                 st.rerun()
#             except Exception as e:
#                 st.error(f"❌ Failed to start simulation: {str(e)}")
        
#         if st.button("⏹️ Stop Simulation", use_container_width=True):
#             try:
#                 st.session_state.traffic_simulator.stop_simulation()
#                 st.session_state.simulation_running = False
#                 st.success("✅ Simulation stopped")
#                 st.rerun()
#             except Exception as e:
#                 st.error(f"❌ Failed to stop simulation: {str(e)}")
        
#         if st.button("🗑️ Clear Results", use_container_width=True):
#             if hasattr(st.session_state.traffic_simulator, 'simulation_results'):
#                 st.session_state.traffic_simulator.simulation_results = []
#             st.success("✅ Simulation results cleared")
#             st.rerun()
    
#     # Simulation tips
#     st.markdown("### 💡 Simulation Tips")
#     st.info("""
#     **How to use the simulator:**
#     1. **Choose Attack Type**: Select the type of DDoS attack to simulate
#     2. **Set Intensity**: Higher values create more aggressive attacks  
#     3. **Start Simulation**: Watch the AI models detect simulated threats in real-time
#     4. **Analyze Results**: Check the detection table and visualizations above
    
#     **Testing Recommendations:**
#     - Start with 50% intensity to see clear detection patterns
#     - Try different attack types to test model versatility
#     - Use 'Normal Traffic' to verify low false-positive rates
#     """)

# def render_documentation():
#     """Render comprehensive system documentation"""
#     st.markdown("# 📚 Complete System Documentation & User Guide")
    
#     # Quick Start Guide
#     st.markdown("## 🚀 Quick Start Guide")
#     st.markdown("""
#     **Getting Started in 3 Simple Steps:**
    
#     1. **🔍 Live Monitoring**: Go to "Live Traffic Monitoring" tab to watch real network traffic
#     2. **🧪 Testing**: Use "Testing & Simulation" tab to test the system with simulated attacks
#     3. **📈 Analysis**: View real-time charts and detection results in both modes
#     """)
    
#     # System Architecture
#     st.markdown("## 🏢 System Architecture")
    
#     # Architecture diagram (text-based)
#     st.markdown("""
#     ```
#     📡 Network Interface (Your WiFi: 192.168.1.105)
#                     │
#                     ↓
#     📦 Packet Capture (Scapy)
#                     │
#                     ↓
#     🔄 Flow Assembly (5-tuple grouping)
#                     │
#                     ↓
#     🔢 Feature Extraction (72 features)
#                     │
#                     ↓
#     🤖 AI Models (LucidCNN + AutoEncoder)
#                     │
#                     ↓
#     📈 Dashboard (Real-time visualization)
#     ```
#     """)
    
#     # How It Works
#     st.markdown("## ⚙️ How the System Works")
    
#     tab1, tab2, tab3, tab4 = st.tabs(["📦 Packet Capture", "🔢 Feature Extraction", "🤖 AI Detection", "📈 Visualization"])
    
#     with tab1:
#         st.markdown("""
#         ### 📦 Packet Capture Process
        
#         **What happens when you click "Start Live Monitoring":**
        
#         1. **Network Interface Detection**: System finds your WiFi adapter (Intel Centrino Wireless-N 135)
#         2. **Packet Sniffing**: Captures TCP and UDP packets from your network (192.168.1.105)
#         3. **Protocol Parsing**: Extracts source/destination IPs, ports, and packet details
#         4. **Flow Grouping**: Groups packets by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        
#         **Indicators you'll see:**
#         - 🟢 **"RECEIVING LIVE TRAFFIC"** when packets are being captured
#         - 🔴 **"NO LIVE TRAFFIC"** when no packets detected
#         - Packet counter showing real-time capture numbers
#         """)
    
#     with tab2:
#         st.markdown("""
#         ### 🔢 Feature Extraction Engine
        
#         **The system extracts 72 statistical features from each network flow:**
        
#         **Packet Size Features (8 features):**
#         - Forward/backward packet length statistics
#         - Min, max, mean, standard deviation of packet sizes
        
#         **Inter-Arrival Time Features (8 features):**
#         - Time gaps between packets in forward/backward directions
#         - Statistical analysis of timing patterns
        
#         **TCP Flag Features (8 features):**
#         - TCP control flags (SYN, ACK, FIN, RST, PSH, URG)
#         - Connection state analysis
        
#         **Flow Duration Features (8 features):**
#         - Total flow duration and sub-flow timings
#         - Active/idle time measurements
        
#         **Additional Statistical Features (40 features):**
#         - Advanced flow characteristics and behavioral patterns
#         - Protocol-specific metrics and anomaly indicators
#         """)
    
#     with tab3:
#         st.markdown("""
#         ### 🤖 AI-Powered Detection
        
#         **Hybrid Detection System using 2 AI Models:**
        
#         **1. LucidCNN (Classification Model)**
#         - **Type**: TensorFlow deep learning classifier
#         - **Input**: 72 normalized features (StandardScaler)
#         - **Output**: Attack probability (0.0 to 1.0)
#         - **Purpose**: Binary classification (Attack vs Benign)
        
#         **2. AutoEncoder (Anomaly Detection)**
#         - **Type**: PyTorch neural network autoencoder  
#         - **Input**: 72 scaled features (MinMaxScaler)
#         - **Output**: Reconstruction error
#         - **Purpose**: Detect unusual patterns in "normal" traffic
        
#         **Final Decision Logic:**
#         ```python
#         if lucid_confidence > 0.5:  # LucidCNN says "Attack"
#             result = "Attack"
#         elif reconstruction_error > threshold:  # AutoEncoder detects anomaly
#             result = "Attack" 
#         else:
#             result = "Benign"
#         ```
        
#         **Threat Levels:**
#         - 🔥 **HIGH**: Both models agree it's an attack
#         - ⚠️ **MEDIUM**: One model detects threat
#         - 🟢 **LOW**: Normal traffic, no threats
#         """)
    
#     with tab4:
#         st.markdown("""
#         ### 📈 Real-Time Visualization
        
#         **What you see in the dashboard:**
        
#         **Status Indicators:**
#         - 🟢 **SYSTEM ACTIVE**: Monitoring is running
#         - 📡 **RECEIVING LIVE TRAFFIC**: Packets being captured
#         - ✅ **Normal Packets**: Benign traffic detected
#         - 🚨 **Attack Packets**: Malicious traffic found
        
#         **Real-Time Metrics:**
#         - **Total Flows**: Number of network flows analyzed
#         - **Detection Rate**: Percentage of traffic flagged as attacks
#         - **Packet Counters**: Live count of normal vs attack packets
        
#         **Interactive Charts:**
#         - **Timeline**: Attack detection over time
#         - **Protocol Analysis**: Which protocols are being attacked
#         - **Threat Sources**: Top attacking IP addresses
#         - **Performance**: System processing speed metrics
#         """)
    
#     # Button Functions
#     st.markdown("## 🔘 Button Functions Guide")
    
#     col1, col2 = st.columns(2)
    
#     with col1:
#         st.markdown("""
#         ### 🔍 Live Monitoring Buttons
        
#         **▶️ Start Live Monitoring**
#         - Begins capturing packets from your network interface
#         - Starts real-time analysis with AI models
#         - Updates dashboard every second with new detections
        
#         **⏹️ Stop Monitoring**
#         - Stops packet capture and analysis
#         - Preserves existing detection results
#         - System goes into idle mode
        
#         **🗑️ Clear Results**
#         - Removes all detection history
#         - Resets metrics and counters
#         - Fresh start for new monitoring session
#         """)
    
#     with col2:
#         st.markdown("""
#         ### 🧪 Simulation Buttons
        
#         **▶️ Start Simulation**
#         - Generates artificial attack traffic
#         - Tests AI models with known attack patterns
#         - Safe testing without real network attacks
        
#         **⏹️ Stop Simulation**
#         - Ends traffic simulation
#         - Preserves simulation results for analysis
#         - Returns to normal monitoring mode
        
#         **Attack Type Selector**
#         - **SYN Flood**: TCP connection exhaustion attack
#         - **UDP Flood**: UDP packet flooding attack
#         - **HTTP Flood**: Web server overload attack
#         - **ICMP Flood**: Ping flooding attack
#         - **Normal Traffic**: Benign traffic for testing
#         """)
    
#     # Network Configuration
#     st.markdown("## 🌐 Your Network Configuration")
    
#     st.info("""
#     **Detected Network Setup:**
#     - **Computer**: VIVEk
#     - **IP Address**: 192.168.1.105
#     - **Network**: 255.255.255.0 (192.168.1.x)
#     - **Gateway**: 192.168.1.1
#     - **WiFi Adapter**: Intel(R) Centrino(R) Wireless-N 135
#     - **DNS Servers**: 8.8.8.8, 103.50.76.14
#     """)
    
#     # Troubleshooting
#     st.markdown("## 🔧 Troubleshooting Guide")
    
#     st.markdown("""
#     **Common Issues & Solutions:**
    
#     **🔴 "NO LIVE TRAFFIC" showing:**
#     - Check if you're connected to WiFi (192.168.1.105)
#     - Try browsing websites to generate network traffic
#     - Restart the monitoring if no packets appear
    
#     **🚨 Too many false alarms:**
#     - This is normal during initial learning
#     - Models improve with more diverse traffic
#     - Use simulation mode to verify detection accuracy
    
#     **⚡ System running slowly:**
#     - High traffic networks may cause delays
#     - Clear results periodically to free memory
#     - Consider reducing monitoring duration
    
#     **🤖 Model errors:**
#     - Ensure all 4 model files are uploaded correctly
#     - Check file sizes match your trained models
#     - Try restarting the system if issues persist
#     """)
    
#     # Best Practices
#     st.markdown("## 🌟 Best Practices")
    
#     st.success("""
#     **For Best Results:**
    
#     1. **Start with Simulation**: Test the system with simulated attacks before live monitoring
#     2. **Monitor During Activity**: Run live monitoring while browsing, downloading, or streaming
#     3. **Check Multiple Attack Types**: Test different simulation types to verify model performance
#     4. **Analyze Patterns**: Look for consistent detection patterns in the timeline charts
#     5. **Clear Results Regularly**: Reset every few hours to maintain optimal performance
#     6. **Monitor Different Times**: Network patterns change throughout the day
#     """)

# if __name__ == "__main__":
#     main()

## app.py

import streamlit as st
import time
import queue
from dashboard import DDOSDetectionDashboard
from traffic_simulator import TrafficSimulator
from packet_capture import PacketCapture
from flow_manager import FlowManager
from model_inference import ModelInference
from prevention_system import PreventionSystem  # Added import
import os

st.set_page_config(
    page_title="Adaptive DDoS Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def initialize_system():
    """Initializes all necessary components in the Streamlit session state."""
    if 'system_initialized' not in st.session_state:
        st.session_state.system_running = False
        st.session_state.simulation_running = False
        st.session_state.flow_queue = queue.Queue(maxsize=2000)
        st.session_state.detection_results = []
        
        # === NEW: State to track if the system has been calibrated ===
        st.session_state.is_calibrated = False
        # =============================================================
        
        required_files = ['lucid.h5', 'lucid.pkl', 'auto.pth', 'auto.pkl']
        if any(not os.path.exists(f) for f in required_files):
            st.error(f"❌ Missing one or more model files. Please ensure all model files are present.")
            st.stop()

        try:
            with st.spinner("Loading AI models..."):
                st.session_state.model_inference = ModelInference()
            st.success("✅ AI Models loaded successfully!")
        except Exception as e:
            st.error(f"❌ Failed to load models: {str(e)}")
            st.stop()
        
        # Initialize Prevention System
        if 'prevention_system' not in st.session_state:
            st.session_state.prevention_system = PreventionSystem(simulation_mode=True)

        st.session_state.traffic_simulator = TrafficSimulator()
        st.session_state.available_interfaces = PacketCapture.get_available_interfaces()
        st.session_state.system_initialized = True

# === NEW FUNCTION: To handle the 60-second calibration process ===
def run_calibration(interface, timeout):
    """
    Captures live traffic for 60 seconds, assumes it's normal,
    and uses it to set the initial adaptive threshold.
    """
    st.session_state.flow_manager = FlowManager(flow_queue=st.session_state.flow_queue, timeout=timeout)
    st.session_state.packet_capture = PacketCapture(interface=interface, flow_manager=st.session_state.flow_manager)
    
    if not st.session_state.packet_capture.interface:
        st.error("❌ Failed to initialize on the selected interface. Cannot calibrate.")
        return

    st.session_state.packet_capture.start_capture_thread()
    
    calibration_errors = []
    progress_bar = st.progress(0, text="Calibrating... Please wait.")
    
    with st.spinner("Learning normal traffic patterns for 60 seconds..."):
        for i in range(60):
            time.sleep(1)
            # Process any flows that completed during this second
            try:
                while not st.session_state.flow_queue.empty():
                    flow_data = st.session_state.flow_queue.get_nowait()
                    # We only need the reconstruction error for calibration
                    result = st.session_state.model_inference.predict(flow_data['features'])
                    calibration_errors.append(result['reconstruction_error'])
            except queue.Empty:
                pass
            progress_bar.progress((i + 1) / 60, text=f"Calibrating... {i+1}/60 seconds complete.")

    st.session_state.packet_capture.stop_capture()
    
    # Initialize the baseline with the collected data
    st.session_state.model_inference.initialize_baseline(calibration_errors)
    st.session_state.is_calibrated = True
    
    progress_bar.empty()
    st.success(f"✅ Calibration complete! Collected {len(calibration_errors)} flow samples. System is ready.")
    time.sleep(2)
    st.rerun()
# ======================================================================

def render_sidebar():
    """Renders the main control sidebar for the application."""
    st.sidebar.title("🛡️ Control Center")
    st.sidebar.markdown("---")
    
    st.sidebar.markdown("### 🛡️ Prevention System")
    prev_mode = st.sidebar.radio(
        "Mode:", 
        ("Simulation (Safe)", "Active (Block IPs)"),
        index=0 if st.session_state.prevention_system.simulation_mode else 1,
        help="Active mode will modify Firewall rules. Simulation only logs."
    )
    
    # Update simulation mode based on selection
    is_simulation = (prev_mode == "Simulation (Safe)")
    if is_simulation != st.session_state.prevention_system.simulation_mode:
        st.session_state.prevention_system.toggle_mode(is_simulation)
        if not is_simulation:
            st.sidebar.warning("⚠️ ACTIVE BLOCKING ENABLED")
    
    # Blocked IPs viewer
    blocked = st.session_state.prevention_system.get_blocked_ips()
    with st.sidebar.expander(f"🚫 Blocked IPs ({len(blocked)})"):
        if blocked:
            for ip in blocked:
                col_a, col_b = st.columns([3, 1])
                col_a.text(ip)
                if col_b.button("❌", key=f"unblock_{ip}", help="Unblock IP"):
                    st.session_state.prevention_system.unblock_ip(ip)
                    st.rerun()
            if st.button("Unblock All", key="unblock_all"):
                st.session_state.prevention_system.clear_all_blocks()
                st.rerun()
        else:
            st.info("No IPs currently blocked.")

    st.sidebar.markdown("---")
    
    st.sidebar.markdown("### 📊 System Status")
    # === MODIFIED: Status now includes calibration state ===
    if st.session_state.is_calibrated:
        st.sidebar.success("Status: Calibrated & Ready")
    else:
        st.sidebar.warning("Status: Uncalibrated")
    # ========================================================
    
    status_color = "🟢" if st.session_state.system_running else "🔴"
    status_text = "ACTIVE" if st.session_state.system_running else "STOPPED"
    st.sidebar.markdown(f"**Detection System:** {status_color} {status_text}")
    st.sidebar.markdown("---")
    
    st.sidebar.markdown("### 🌐 Network Configuration")
    if not st.session_state.available_interfaces:
        st.sidebar.error("No network interfaces found!")
        selected_interface = None
    else:
        selected_interface = st.sidebar.selectbox(
            "Select Network Interface", st.session_state.available_interfaces,
            index=0 if not PacketCapture.auto_detect_interface() in st.session_state.available_interfaces else st.session_state.available_interfaces.index(PacketCapture.auto_detect_interface())
        )
    flow_timeout = st.sidebar.slider("Flow Timeout (s)", 5, 30, 15)
    st.sidebar.markdown("---")
    
    # === MODIFIED: New two-step UI for calibration and detection ===
    st.sidebar.markdown("### 🎯 Real Traffic Detection")
    st.sidebar.info("System must be calibrated on normal traffic before detection can start.")

    if st.sidebar.button("Step 1: Calibrate System", disabled=st.session_state.is_calibrated, use_container_width=True, type="secondary"):
        if selected_interface:
            run_calibration(selected_interface, flow_timeout)
        else:
            st.sidebar.error("Please select a valid interface first.")
            
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("Step 2: Start Detection", disabled=not st.session_state.is_calibrated or st.session_state.system_running, key="start_detection", use_container_width=True, type="primary"):
            start_detection_system(selected_interface, flow_timeout)
    with col2:
        if st.button("Stop Detection", disabled=not st.session_state.system_running, key="stop_detection", use_container_width=True):
            stop_detection_system()
    # ======================================================================
    st.sidebar.markdown("---")
    st.sidebar.info("Simulator controls are in the 'Testing & Simulation' tab.")


def start_detection_system(interface, timeout):
    """Initializes and starts the DDoS detection system."""
    try:
        with st.spinner(f"Initializing capture on {interface}..."):
            st.session_state.flow_manager = FlowManager(
                flow_queue=st.session_state.flow_queue, timeout=timeout
            )
            st.session_state.packet_capture = PacketCapture(
                interface=interface, flow_manager=st.session_state.flow_manager
            )
        
        if not st.session_state.packet_capture.interface:
            st.error("❌ Failed to initialize on the selected interface.")
            return
        
        st.session_state.packet_capture.start_capture_thread()
        st.session_state.system_running = True
        st.success(f"✅ Detection system LIVE on interface: {interface}")
        time.sleep(1) 
        st.rerun()
    except Exception as e:
        st.error(f"❌ Failed to start detection system: {e}")
        st.session_state.system_running = False

def stop_detection_system():
    """Stops the DDoS detection system."""
    if st.session_state.packet_capture:
        st.session_state.packet_capture.stop_capture()
    st.session_state.system_running = False
    st.warning("⚠️ Detection system stopped.")
    time.sleep(1)
    st.rerun()

def process_flows():
    """Processes flows from the queue and updates results."""
    processed_count = 0
    max_per_cycle = 50
    
    try:
        while not st.session_state.flow_queue.empty() and processed_count < max_per_cycle:
            flow_data = st.session_state.flow_queue.get_nowait()
            result = st.session_state.model_inference.predict(flow_data['features'])
            detection_result = {**flow_data, **result}
            
            # === INTEGRATE PREVENTION SYSTEM ===
            if result['threat_level'] == 'HIGH':
                source_ip = flow_data['src_ip']
                blocked = st.session_state.prevention_system.block_ip(source_ip, reason="High Threat DDoS")
                if blocked:
                    detection_result['status'] = 'BLOCKED'
                else:
                    detection_result['status'] = 'FLAGGED'
            # ==================================
            
            st.session_state.detection_results.append(detection_result)
            if len(st.session_state.detection_results) > 1500:
                st.session_state.detection_results = st.session_state.detection_results[-1000:]
            
            processed_count += 1
    except queue.Empty:
        pass
    except Exception as e:
        st.error(f"Error processing flows: {str(e)}")


def render_documentation():
    """Renders the documentation tab."""
    st.header("📚 Documentation & Guide")
    st.markdown("""
    This system uses a hybrid AI approach to detect DDoS attacks in real-time.
    - **LucidCNN**: A deep learning model for classifying known attack patterns.
    - **Autoencoder**: An anomaly detection model to spot unusual, potentially new attacks.
    - **Live Monitoring**: Captures and analyzes traffic directly from your network interface.
    - **Simulator**: Safely test the system's detection capabilities with generated attack traffic.
    - **Tuning**: The model thresholds have been custom-tuned to balance accuracy and reduce false alarms.
    """)
    st.info("This is the final, fully functional version of the DDoS Detection System.")

def main():
    """The main execution function for the Streamlit app."""
    initialize_system()
    render_sidebar()
    dashboard = DDOSDetectionDashboard()
    
    tab1, tab2, tab3 = st.tabs(["🔍 Live Traffic Monitoring", "🧪 Testing & Simulation", "📚 Documentation & Guide"])
    
    with tab1:
        # === MODIFIED: Pass the current threshold to the dashboard ===
        current_threshold = st.session_state.model_inference.current_autoencoder_threshold if st.session_state.is_calibrated else "N/A"
        dashboard.render_live_monitoring(
            detection_results=st.session_state.detection_results, 
            system_running=st.session_state.system_running,
            current_threshold=current_threshold
        )
        # =============================================================
    
    with tab2:
        st.header("🎲 Traffic Simulator Controls")
        # ... (rest of the simulator UI remains the same)
        sim_attack_type = st.selectbox(
            "Attack Type to Simulate", 
            st.session_state.traffic_simulator.attack_options
        )
        sim_intensity = st.slider(
            "Attack Intensity", 0.0, 1.0, 0.8, 0.1
        )
        sim_packet_rate = st.slider(
            "Packet Rate (flows/sec)", 5, 100, 25, 5
        )
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Simulation", disabled=st.session_state.simulation_running, key="start_sim", use_container_width=True):
                st.session_state.traffic_simulator.set_attack_parameters(sim_attack_type, sim_intensity, sim_packet_rate)
                st.session_state.traffic_simulator.start_simulation(st.session_state.flow_queue)
                st.session_state.simulation_running = True
                st.rerun()
        with col2:
            if st.button("Stop Simulation", disabled=not st.session_state.simulation_running, key="stop_sim", use_container_width=True):
                st.session_state.traffic_simulator.stop_simulation()
                st.session_state.simulation_running = False
                st.rerun()
        st.markdown("---")
        dashboard._render_enhanced_detection_table(st.session_state.detection_results)

    with tab3:
        render_documentation() # Placeholder
    
    if st.session_state.system_running or st.session_state.simulation_running:
        process_flows()
        time.sleep(1.0)
        st.rerun()

if __name__ == "__main__":
    main()