import streamlit as st
import threading
import time
import queue
from enhanced_dashboard import EnhancedDDOSDetectionDashboard
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
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "Advanced DDoS Detection System with AI-powered threat analysis"
    }
)

def main():
    # Initialize session state with enhanced components
    if 'system_running' not in st.session_state:
        st.session_state.system_running = False
    if 'flow_queue' not in st.session_state:
        st.session_state.flow_queue = queue.Queue(maxsize=1000)
    if 'detection_results' not in st.session_state:
        st.session_state.detection_results = []
    if 'flow_manager' not in st.session_state:
        st.session_state.flow_manager = None
    if 'packet_capture' not in st.session_state:
        st.session_state.packet_capture = None
    if 'model_inference' not in st.session_state:
        st.session_state.model_inference = None
    if 'traffic_simulator' not in st.session_state:
        st.session_state.traffic_simulator = TrafficSimulator()
    if 'simulation_running' not in st.session_state:
        st.session_state.simulation_running = False
    if 'performance_metrics' not in st.session_state:
        st.session_state.performance_metrics = {
            'start_time': time.time(),
            'packets_processed': 0,
            'flows_analyzed': 0,
            'threats_detected': 0
        }

    # Check for required model files
    required_files = ['lucid.h5', 'lucid.pkl', 'auto.pth', 'auto.pkl']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        st.error(f"❌ Missing required model files: {', '.join(missing_files)}")
        st.info("Please upload the following files to the root directory:")
        for file in missing_files:
            st.write(f"- {file}")
        
        st.markdown("### 📋 Model File Requirements:")
        st.markdown("""
        - **lucid.h5**: Your trained LucidCNN TensorFlow model
        - **lucid.pkl**: StandardScaler for LucidCNN preprocessing  
        - **auto.pth**: Your trained AutoEncoder PyTorch model
        - **auto.pkl**: MinMaxScaler and threshold for AutoEncoder
        """)
        st.stop()

    # Initialize components
    if st.session_state.model_inference is None:
        try:
            with st.spinner("Loading AI models..."):
                st.session_state.model_inference = ModelInference()
            st.success("✅ AI Models loaded successfully!")
            st.balloons()
        except Exception as e:
            st.error(f"❌ Failed to load models: {str(e)}")
            st.stop()

    # Enhanced sidebar with professional styling
    render_enhanced_sidebar()
    
    # Create enhanced dashboard
    dashboard = EnhancedDDOSDetectionDashboard()
    
    # Get simulation stats
    simulation_stats = st.session_state.traffic_simulator.get_simulation_stats()
    
    # Display enhanced dashboard
    dashboard.render(
        st.session_state.detection_results, 
        st.session_state.system_running,
        simulation_stats
    )
    
    # Auto-refresh when system is running
    if st.session_state.system_running or st.session_state.simulation_running:
        time.sleep(1)
        st.rerun()

def render_enhanced_sidebar():
    """Render enhanced sidebar with all controls"""
    
    # Main header
    st.sidebar.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 10px; color: white; text-align: center; margin-bottom: 1rem;">
        <h2>🛡️ Control Center</h2>
        <p>DDoS Detection System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # System Status
    st.sidebar.markdown("### 📊 System Status")
    status_color = "🟢" if st.session_state.system_running else "🔴"
    status_text = "ACTIVE" if st.session_state.system_running else "STOPPED"
    st.sidebar.markdown(f"**Detection System:** {status_color} {status_text}")
    
    sim_color = "🟢" if st.session_state.simulation_running else "🔴"
    sim_text = "ACTIVE" if st.session_state.simulation_running else "STOPPED"
    st.sidebar.markdown(f"**Traffic Simulator:** {sim_color} {sim_text}")
    
    st.sidebar.markdown("---")
    
    # Network Interface Selection
    st.sidebar.markdown("### 🌐 Network Configuration")
    interfaces = ["lo", "eth0", "wlan0", "any"]
    selected_interface = st.sidebar.selectbox(
        "Select Network Interface", 
        interfaces,
        help="Choose the network interface to monitor"
    )
    
    # Flow timeout setting
    flow_timeout = st.sidebar.slider(
        "Flow Timeout (seconds)", 
        5, 30, 10,
        help="Time after which inactive flows are processed"
    )
    
    st.sidebar.markdown("---")
    
    # Real Traffic Detection Controls
    st.sidebar.markdown("### 🎯 Real Traffic Detection")
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("🟢 Start Detection", disabled=st.session_state.system_running):
            start_detection_system(selected_interface, flow_timeout)
    
    with col2:
        if st.button("🔴 Stop Detection", disabled=not st.session_state.system_running):
            stop_detection_system()
    
    st.sidebar.markdown("---")
    
    # Traffic Simulator Controls
    st.sidebar.markdown("### 🎲 Traffic Simulator")
    st.sidebar.markdown("*Test the system with simulated traffic*")
    
    # Attack type selection
    attack_types = ["Normal Traffic", "SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood"]
    selected_attack = st.sidebar.selectbox("Attack Type", attack_types)
    
    # Attack intensity
    attack_intensity = st.sidebar.slider(
        "Attack Intensity", 
        0.0, 1.0, 0.5, 0.1,
        help="0 = Normal traffic, 1 = Full attack"
    )
    
    # Packet rate
    packet_rate = st.sidebar.slider(
        "Packet Rate (pkt/s)", 
        1, 50, 10,
        help="Number of packets generated per second"
    )
    
    # Simulator controls
    col3, col4 = st.sidebar.columns(2)
    
    with col3:
        if st.button("🎯 Start Simulator", disabled=st.session_state.simulation_running):
            start_traffic_simulator(selected_attack, attack_intensity, packet_rate)
    
    with col4:
        if st.button("⏹️ Stop Simulator", disabled=not st.session_state.simulation_running):
            stop_traffic_simulator()
    
    st.sidebar.markdown("---")
    
    # Performance Metrics
    st.sidebar.markdown("### ⚡ Performance")
    if st.session_state.detection_results:
        metrics = st.session_state.performance_metrics
        current_time = time.time()
        uptime = current_time - metrics['start_time']
        
        st.sidebar.metric("Uptime", f"{int(uptime//3600)}h {int((uptime%3600)//60)}m")
        st.sidebar.metric("Total Flows", len(st.session_state.detection_results))
        
        threats = [r for r in st.session_state.detection_results if r['final_prediction'] == 'Attack']
        st.sidebar.metric("Threats Detected", len(threats))
        
        if uptime > 0:
            flow_rate = len(st.session_state.detection_results) / uptime
            st.sidebar.metric("Processing Rate", f"{flow_rate:.1f} flows/s")
    
    st.sidebar.markdown("---")
    
    # System Controls
    st.sidebar.markdown("### 🔧 System Controls")
    if st.sidebar.button("🗑️ Clear Results"):
        st.session_state.detection_results.clear()
        st.success("Results cleared!")
        st.rerun()
    
    if st.sidebar.button("🔄 Reset System"):
        reset_system()
        st.success("System reset!")
        st.rerun()

def start_detection_system(interface, timeout):
    """Start the DDoS detection system"""
    try:
        # Initialize flow manager
        st.session_state.flow_manager = FlowManager(
            flow_queue=st.session_state.flow_queue,
            timeout=timeout
        )
        
        # Initialize packet capture
        st.session_state.packet_capture = PacketCapture(
            interface=interface,
            flow_manager=st.session_state.flow_manager
        )
        
        # Start processing threads
        capture_thread = threading.Thread(
            target=st.session_state.packet_capture.start_capture,
            daemon=True
        )
        
        processing_thread = threading.Thread(
            target=process_flows,
            daemon=True
        )
        
        capture_thread.start()
        processing_thread.start()
        
        st.session_state.system_running = True
        st.success(f"✅ Detection system started on interface: {interface}")
        
    except Exception as e:
        st.error(f"❌ Failed to start detection system: {str(e)}")

def stop_detection_system():
    """Stop the DDoS detection system"""
    st.session_state.system_running = False
    if st.session_state.packet_capture:
        st.session_state.packet_capture.stop_capture()
    st.warning("⚠️ Detection system stopped")

def start_traffic_simulator(attack_type, intensity, packet_rate):
    """Start traffic simulator"""
    try:
        # Configure simulator parameters
        st.session_state.traffic_simulator.set_attack_parameters(
            attack_type, intensity, packet_rate
        )
        
        # Start simulator
        st.session_state.traffic_simulator.start_simulation(
            st.session_state.flow_queue
        )
        
        st.session_state.simulation_running = True
        st.success(f"✅ Traffic simulator started: {attack_type} (Intensity: {intensity:.1%})")
        
    except Exception as e:
        st.error(f"❌ Failed to start traffic simulator: {str(e)}")

def stop_traffic_simulator():
    """Stop traffic simulator"""
    st.session_state.traffic_simulator.stop_simulation()
    st.session_state.simulation_running = False
    st.warning("⚠️ Traffic simulator stopped")

def reset_system():
    """Reset the entire system"""
    # Stop all processes
    st.session_state.system_running = False
    st.session_state.simulation_running = False
    
    if st.session_state.packet_capture:
        st.session_state.packet_capture.stop_capture()
    
    if st.session_state.traffic_simulator:
        st.session_state.traffic_simulator.stop_simulation()
    
    # Clear data
    st.session_state.detection_results.clear()
    st.session_state.flow_queue = queue.Queue(maxsize=1000)
    
    # Reset metrics
    st.session_state.performance_metrics = {
        'start_time': time.time(),
        'packets_processed': 0,
        'flows_analyzed': 0,
        'threats_detected': 0
    }

def process_flows():
    """Enhanced flow processing with performance tracking"""
    while st.session_state.system_running or st.session_state.simulation_running:
        try:
            if not st.session_state.flow_queue.empty():
                flow_data = st.session_state.flow_queue.get_nowait()
                
                # Perform model inference
                result = st.session_state.model_inference.predict(flow_data['features'])
                
                # Create enhanced detection result
                detection_result = {
                    'timestamp': flow_data['timestamp'],
                    'src_ip': flow_data['src_ip'],
                    'dst_ip': flow_data['dst_ip'],
                    'src_port': flow_data['src_port'],
                    'dst_port': flow_data['dst_port'],
                    'protocol': flow_data['protocol'],
                    'lucid_prediction': result['lucid_prediction'],
                    'lucid_confidence': result['lucid_confidence'],
                    'autoencoder_anomaly': result['autoencoder_anomaly'],
                    'reconstruction_error': result['reconstruction_error'],
                    'final_prediction': result['final_prediction'],
                    'threat_level': result['threat_level'],
                    'features': flow_data['features']  # Store features for analysis
                }
                
                # Add to results with size limit for performance
                st.session_state.detection_results.append(detection_result)
                if len(st.session_state.detection_results) > 2000:
                    st.session_state.detection_results = st.session_state.detection_results[-1500:]
                
                # Update performance metrics
                st.session_state.performance_metrics['flows_analyzed'] += 1
                if result['final_prediction'] == 'Attack':
                    st.session_state.performance_metrics['threats_detected'] += 1
            
            time.sleep(0.05)  # Optimized delay for better performance
            
        except queue.Empty:
            time.sleep(0.1)
        except Exception as e:
            st.error(f"Error processing flows: {str(e)}")
            time.sleep(1)

if __name__ == "__main__":
    main()