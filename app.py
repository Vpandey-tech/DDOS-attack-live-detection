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

import streamlit as st
import threading
import time
import queue
from dashboard import DDOSDetectionDashboard
from traffic_simulator import TrafficSimulator
from packet_capture import PacketCapture
from flow_manager import FlowManager
from model_inference import ModelInference
import os
import sys

# Configure Streamlit page with enhanced settings
st.set_page_config(
    page_title="Advanced DDoS Detection System",
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
        
        required_files = ['lucid.h5', 'lucid.pkl', 'auto.pth', 'auto.pkl']
        missing_files = [f for f in required_files if not os.path.exists(f)]
        
        if missing_files:
            st.error(f"❌ Missing required model files: {', '.join(missing_files)}")
            st.stop()

        try:
            with st.spinner("Loading AI models..."):
                st.session_state.model_inference = ModelInference()
            st.success("✅ AI Models loaded successfully!")
        except Exception as e:
            st.error(f"❌ Failed to load models: {str(e)}")
            st.stop()
        
        st.session_state.flow_manager = None
        st.session_state.packet_capture = None
        st.session_state.traffic_simulator = TrafficSimulator()
        st.session_state.available_interfaces = PacketCapture.get_available_interfaces()
        st.session_state.system_initialized = True

def render_sidebar():
    """Renders the main control sidebar for the application."""
    st.sidebar.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 10px; color: white; text-align: center; margin-bottom: 1rem;">
        <h2>🛡️ Control Center</h2>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("### 📊 System Status")
    status_color = "🟢" if st.session_state.system_running else "🔴"
    status_text = "ACTIVE" if st.session_state.system_running else "STOPPED"
    st.sidebar.markdown(f"**Detection System:** {status_color} {status_text}")
    
    sim_color = "🟢" if st.session_state.simulation_running else "🔴"
    sim_text = "ACTIVE" if st.session_state.simulation_running else "STOPPED"
    st.sidebar.markdown(f"**Traffic Simulator:** {sim_color} {sim_text}")
    st.sidebar.markdown("---")
    
    st.sidebar.markdown("### 🌐 Network Configuration")
    auto_detected_interface = PacketCapture.auto_detect_interface()
    try:
        default_index = st.session_state.available_interfaces.index(auto_detected_interface)
    except (ValueError, TypeError):
        default_index = 0

    if not st.session_state.available_interfaces:
        st.sidebar.error("No network interfaces found!")
        selected_interface = None
    else:
        selected_interface = st.sidebar.selectbox(
            "Select Network Interface",
            st.session_state.available_interfaces,
            index=default_index
        )

    flow_timeout = st.sidebar.slider("Flow Timeout (s)", 5, 30, 10)
    st.sidebar.markdown("---")
    
    st.sidebar.markdown("### 🎯 Real Traffic Detection")
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("🟢 Start Detection", disabled=st.session_state.system_running or not selected_interface, use_container_width=True):
            start_detection_system(selected_interface, flow_timeout)
    with col2:
        if st.button("🔴 Stop Detection", disabled=not st.session_state.system_running, use_container_width=True):
            stop_detection_system()

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🎲 Traffic Simulator")
    st.sidebar.info("Controls are in the 'Testing & Simulation' tab.")

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
    if st.session_state.packet_capture:
        st.session_state.packet_count = st.session_state.packet_capture.packet_count

    try:
        while not st.session_state.flow_queue.empty() and processed_count < max_per_cycle:
            flow_data = st.session_state.flow_queue.get_nowait()
            result = st.session_state.model_inference.predict(flow_data['features'])
            detection_result = {**flow_data, **result}
            st.session_state.detection_results.append(detection_result)
            if len(st.session_state.detection_results) > 1000:
                st.session_state.detection_results.pop(0)
            processed_count += 1
    except queue.Empty:
        pass
    except Exception as e:
        st.error(f"Error processing flows: {str(e)}")

def render_documentation():
    """Renders the comprehensive system documentation and user guide tab."""
    st.markdown("# 📚 Complete System Documentation & User Guide")
    st.markdown("## 🚀 Quick Start Guide")
    st.info("""
    **Getting Started in 3 Simple Steps:**
    1.  **Select Interface**: Choose your active network card (e.g., Wi-Fi) from the sidebar.
    2.  **Start Detection**: Click "Start Detection" to begin live monitoring.
    3.  **Analyze**: Watch the dashboard populate with real-time metrics, alerts, and results.
    """)

    st.markdown("## 🏢 System Architecture")
    st.markdown("""
    The system follows a modular, multi-threaded architecture to ensure high performance and real-time processing.
    ```
    [User Interface - Streamlit] <--> [Flask Backend - app.py]
                                              |
    +-----------------------------------------+------------------------------------------+
    |                                         |                                          |
    V                                         V                                          V
    [Packet Capture Thread]             [Flow Manager Thread]                      [AI Inference Engine]
    (packet_capture.py)                   (flow_manager.py)                          (model_inference.py)
    - Captures raw packets                - Assembles packets into flows             - Pre-processes features
    - Uses Scapy & Psutil                 - Manages flow timeouts                    - Predicts with LucidCNN
    - Sends packets to Flow Manager         - Extracts 72 features per flow          - Predicts with Autoencoder
                                          - Pushes flows to queue                    - Returns hybrid result
    ```
    """)

    st.markdown("## ⚙️ How It Works: A Deep Dive")
    tab1, tab2, tab3 = st.tabs(["📦 Packet Capture & Flow Assembly", "🤖 AI Detection Engine", "📈 Dashboard & Visualization"])
    
    with tab1:
        st.markdown("### Packet Capture")
        st.write("""
        - **Initialization**: When you click "Start Detection", the `PacketCapture` module is initialized on your selected network interface.
        - **Sniffing**: It runs `Scapy.sniff` in a dedicated background thread, ensuring the UI remains responsive.
        - **Packet Handling**: Each captured packet is timestamped and basic info (IPs, ports, protocol) is extracted.
        - **Efficiency**: It operates in a memory-safe mode (`store=False`), immediately passing packets for processing without storing them.
        
        ### Flow Assembly
        - **Bi-directional Flows**: The `FlowManager` receives individual packets and groups them into bi-directional flows using a unique 5-tuple key (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
        - **Timeout Mechanism**: A flow is considered complete and ready for analysis if no new packets are added to it within a specific timeout period (configurable in the sidebar).
        - **Feature Extraction**: Once a flow expires, the `FeatureExtractor` calculates 72 statistical features (e.g., packet sizes, inter-arrival times, TCP flags) that describe the flow's behavior.
        - **Processing Queue**: The finalized flow with its features is placed into a thread-safe queue, ready for the AI engine.
        """)
    
    with tab2:
        st.markdown("### The Hybrid AI Model")
        st.write("The system uses a powerful hybrid approach, combining two different AI models for superior accuracy.")
        
        st.markdown("#### 1. LucidCNN (Deep Learning Classifier)")
        st.warning("""
        - **Purpose**: To classify a flow as either **Benign** or **Attack**.
        - **Architecture**: A Convolutional Neural Network (CNN) trained on labeled DDoS attack data.
        - **Strength**: Excellent at recognizing the specific patterns and signatures of known attack types.
        - **Output**: A confidence score (0.0 to 1.0) indicating the probability of the flow being an attack.
        """)

        st.markdown("#### 2. Autoencoder (Anomaly Detector)")
        st.info("""
        - **Purpose**: To identify network flows that are **anomalous** or unusual.
        - **Architecture**: A PyTorch-based neural network trained *only* on benign (normal) traffic.
        - **Strength**: Can detect new, zero-day attacks that don't match known signatures, because it flags anything that deviates from the learned pattern of "normal."
        - **Output**: A reconstruction error. High error means the traffic is anomalous.
        """)

        st.markdown("#### Final Decision Logic")
        st.success("""
        A flow is flagged as an **Attack** if **EITHER** of these conditions is met:
        - The **LucidCNN** model is highly confident it's an attack.
        - The **Autoencoder** model flags the flow as a high-error anomaly.
        
        This hybrid logic provides the best of both worlds: high accuracy for known threats and a safety net for unknown ones.
        """)

    with tab3:
        st.markdown("### Real-Time Visualization")
        st.write("""
        - **State Management**: The UI is built with Streamlit, which uses a session state to store all real-time data like detection results and system status.
        - **Data Loop**: The `app.py` script runs a main loop that periodically pulls processed flows from the queue and updates the session state.
        - **Auto-Refresh**: The `st.rerun()` command is called at the end of the loop, forcing the entire dashboard to redraw with the latest data, creating the real-time effect.
        - **Component-Based UI**: The `dashboard.py` file contains a class that renders all the visual components (metrics, charts, tables) based on the data it receives from the session state. This keeps the UI code clean and separated from the main application logic.
        """)

def main():
    """The main execution function for the Streamlit app."""
    initialize_system()
    render_sidebar()
    dashboard = DDOSDetectionDashboard()
    
    tab1, tab2, tab3 = st.tabs(["🔍 Live Traffic Monitoring", "🧪 Testing & Simulation", "📚 Documentation & Guide"])
    
    with tab1:
        dashboard.render_live_monitoring(st.session_state.detection_results, st.session_state.system_running)
    
    with tab2:
        st.info("The traffic simulator allows you to test the model's detection capabilities safely.")
        # You would integrate your traffic_simulator controls and display logic here
        # For now, this is a placeholder.
        st.markdown("### Simulator Controls")
        sim_attack_type = st.selectbox("Attack Type to Simulate", ["Normal Traffic", "SYN Flood", "UDP Flood"])
        if st.button("Start Simulation"):
            st.session_state.simulation_running = True
            st.success(f"Simulating {sim_attack_type}...")
        if st.button("Stop Simulation"):
            st.session_state.simulation_running = False
            st.warning("Simulation stopped.")


    with tab3:
        render_documentation()
    
    if st.session_state.system_running or st.session_state.simulation_running:
        process_flows()
        time.sleep(1.5)
        st.rerun()

if __name__ == "__main__":
    main()

