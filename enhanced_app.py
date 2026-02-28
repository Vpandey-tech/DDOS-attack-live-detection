import streamlit as st
import threading
import time
import queue
from enhanced_dashboard import EnhancedDDOSDetectionDashboard
from traffic_simulator import TrafficSimulator
from packet_capture import PacketCapture
from flow_manager import FlowManager
from model_inference import ModelInference
from prevention_system import PreventionSystem
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
    if 'prevention_system' not in st.session_state:
        st.session_state.prevention_system = PreventionSystem(simulation_mode=True)
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
    if 'calibration_active' not in st.session_state:
        st.session_state.calibration_active = False
    if 'calibration_done' not in st.session_state:
        st.session_state.calibration_done = False
    if 'calibration_start_time' not in st.session_state:
        st.session_state.calibration_start_time = 0
    if 'performance_metrics' not in st.session_state:
        st.session_state.performance_metrics = {
            'start_time': time.time(),
            'packets_processed': 0,
            'flows_analyzed': 0,
            'threats_detected': 0
        }

    # Check for required model files
    required_files = ['lucid.h5', 'lucid.pkl', 'auto.pth', 'auto.pkl', 'xgboost_ddos.pkl', 'random_forest_ddos.pkl']
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
        - **xgboost_ddos.pkl**: XGBoost Ensemble Model
        - **random_forest_ddos.pkl**: Random Forest Ensemble Model
        """)
        st.stop()

    # Initialize components
    if st.session_state.model_inference is None:
        try:
            with st.spinner("Loading AI models..."):
                st.session_state.model_inference = ModelInference()
            st.success("✅ AI Models loaded successfully!")
        except Exception as e:
            st.error(f"❌ Failed to load models: {str(e)}")
            st.stop()

    # Enhanced sidebar with professional styling
    render_enhanced_sidebar()
    
    # Create dashboard and get stats
    dashboard = EnhancedDDOSDetectionDashboard()
    simulation_stats = st.session_state.traffic_simulator.get_simulation_stats()
    
    # Get packet count safely
    current_packet_count = 0
    if st.session_state.packet_capture:
        current_packet_count = st.session_state.packet_capture.packet_count
    
    # Display enhanced dashboard
    dashboard.render(
        st.session_state.detection_results, 
        st.session_state.system_running,
        simulation_stats
    )

    # Auto-refresh when system is running
    # Synchronous processing loop for real-time updates
    if st.session_state.system_running or st.session_state.simulation_running:
        process_flows()
        time.sleep(1) 
        st.rerun()

def run_calibration(interface, timeout):
    """
    Synchronous Calibration Function (Robust Pattern)
    Captures live traffic for 60 seconds, assumes it's normal,
    and uses it to set the initial adaptive threshold.
    """
    # 1. Initialize temporary capture components
    calib_queue = queue.Queue()
    calib_manager = FlowManager(flow_queue=calib_queue, timeout=timeout)
    calib_capture = PacketCapture(interface=interface, flow_manager=calib_manager)
    
    if not calib_capture.interface:
        st.error("❌ Failed to initialize on the selected interface. Cannot calibrate.")
        return

    # 2. Start Capture in Background Thread
    st.session_state.model_inference.start_calibration()
    calib_capture.start_capture_thread()
    
    # 3. Synchronous Progress Loop (Guarantees Visuals)
    calibration_errors = []
    
    # Full screen overlay style for calibration
    placeholder = st.empty()
    
    with placeholder.container():
        st.markdown("""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 3rem; border-radius: 15px; text-align: center; margin: 2rem 0;">
            <h1 style="color: white; font-size: 3rem;">⚖️ CALIBRATING SYSTEM</h1>
            <h3 style="color: #e0e7ff;">Learning Network Baseline...</h3>
             <p style="color: #fff; font-size: 1.2rem; margin-top: 1rem; background: rgba(255,255,255,0.2); padding: 10px; border-radius: 8px;">
                ℹ️ <strong>Instruction:</strong> Please use your device in a normal way (browse web, watch video) for 1 minute to establish an accurate baseline.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        progress_bar = st.progress(0, text="Initializing...")
        metrics_col = st.empty()
    
    try:
        total_seconds = 60
        for i in range(total_seconds):
            time.sleep(1) # Wait for packets to flow
            
            # Process ANY collected flows immediately
            processed = 0
            while not calib_queue.empty():
                try:
                    flow_data = calib_queue.get_nowait()
                    # Only run AutoEncoder
                    is_anomaly, error = st.session_state.model_inference.autoencoder_predict(flow_data['features'])
                    calibration_errors.append(error)
                    processed += 1
                except queue.Empty:
                    break
            
            # Update Visuals
            progress = (i + 1) / total_seconds
            progress_bar.progress(progress, text=f"Calibrating... {i+1}/{total_seconds}s (Samples: {len(calibration_errors)})")
            
    except Exception as e:
        st.error(f"Calibration failed: {e}")
    finally:
        # 4. Cleanup
        calib_capture.stop_capture()
        placeholder.empty()

    # 5. Finalize
    st.session_state.model_inference.initialize_baseline(calibration_errors)
    st.session_state.calibration_done = True
    st.session_state.calibration_active = False # Reset legacy flag if any
    
    # Success Animation
    st.balloons()
    st.success(f"✅ Calibration Complete! Collected {len(calibration_errors)} flow samples.")
    time.sleep(2)
    st.rerun()

def render_enhanced_sidebar():
    """Render enhanced sidebar with all controls"""
    
    # Check if calibration is active - if so, lock all controls
    calibration_active = st.session_state.get('calibration_active', False)
    
    # Main header
    st.sidebar.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 1rem; border-radius: 10px; color: white; text-align: center; margin-bottom: 1rem;">
        <h2>🛡️ Control Center</h2>
        <p>DDoS Detection System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # System Status (Compact)
    # Status now includes calibration state
    if st.session_state.get('calibration_done'):
        st.sidebar.success("Status: Ready (Calibrated)")
    else:
        st.sidebar.warning("Status: Uncalibrated")

    c1, c2 = st.sidebar.columns(2)
    with c1:
        st.info(f"**Detector**\n{'🟢 Active' if st.session_state.system_running else '🔴 Stopped'}")
    with c2:
        st.info(f"**Simulator**\n{'🟢 Active' if st.session_state.simulation_running else '🔴 Stopped'}")
    
    st.sidebar.markdown("---")
    
    # ---------------------------------------------------------
    # STEP 1: INITIALIZATION (Network + Calibration)
    # ---------------------------------------------------------
    st.sidebar.markdown("### 1️⃣ Initialization")
    
    # Network Interface Selection
    available_interfaces = PacketCapture.get_available_interfaces()
    if not available_interfaces:
        available_interfaces = ["lo", "eth0", "wlan0", "any"]
    
    default_index = 0
    
    # Optimize: Cache auto-detection to avoid running it every refresh (every 0.5s)
    if 'auto_detected_iface' not in st.session_state:
        st.session_state.auto_detected_iface = PacketCapture.auto_detect_interface()
    
    auto_detected = st.session_state.auto_detected_iface
    
    if auto_detected and auto_detected in available_interfaces:
        default_index = available_interfaces.index(auto_detected)
        
    selected_interface = st.sidebar.selectbox(
        "Network Interface", 
        available_interfaces,
        index=default_index,
        disabled=calibration_active  # LOCK during calibration
    )
    
    if auto_detected:
        st.sidebar.caption(f"✨ Auto-detected: {auto_detected}")

    # Calibration Control
    calibration_done = st.session_state.get('calibration_done', False)
    flow_timeout = st.sidebar.slider("Flow Timeout (s)", 5, 30, 10, disabled=calibration_active)
    
    # SYNCHRONOUS CALIBRATION LOGIC (Inspired by Reference)
    if not calibration_done:
        st.sidebar.warning("⚠️ System needs calibration")
        if st.sidebar.button("🎯 Start Calibration (60s)", type="primary", disabled=calibration_active):
            # Calling the synchronous function directly!
            run_calibration(selected_interface, flow_timeout)
    else:
        st.sidebar.success("✅ System Calibrated")
        if st.sidebar.button("🔄 Recalibrate", help="Run if network conditions change", disabled=calibration_active):
            # Reset and Run
            st.session_state.calibration_done = False
            run_calibration(selected_interface, flow_timeout)

    st.sidebar.markdown("---")

    # ---------------------------------------------------------
    # STEP 2: REAL-TIME DETECTION (Prevention)
    # ---------------------------------------------------------
    st.sidebar.markdown("### 2️⃣ Detection & Defense")
    
    # Prevention Toggle (Active Blocking)
    prev_system = st.session_state.prevention_system
    # Use a callback or direct check to avoid double-click issues
    active_prevention = st.sidebar.checkbox(
        "🛡️ Active Blocking Mode", 
        value=not prev_system.simulation_mode,
        help="When enabled, malicious IPs are automatically blocked via Firewall.",
        disabled=calibration_active  # LOCK during calibration
    )
    
    # Update state only if changed
    if active_prevention != (not prev_system.simulation_mode):
        prev_system.toggle_mode(not active_prevention)
        st.rerun()

    if active_prevention:
        st.sidebar.caption("⚠️ Firewall Ban Enabled")

    col1, col2 = st.sidebar.columns(2)
    with col1:
        # Disable Start if already running OR if not calibrated (strict mode) OR if calibrating
        start_disabled = st.session_state.system_running or not calibration_done or calibration_active
        if st.sidebar.button("▶ Start", disabled=start_disabled, type="primary"):
            start_detection_system(selected_interface, flow_timeout)
            
    with col2:
        if st.sidebar.button("⏹ Stop", disabled=not st.session_state.system_running or calibration_active):
            stop_detection_system()

    st.sidebar.markdown("---")

    # ---------------------------------------------------------
    # STEP 3: TESTING (Simulator)
    # ---------------------------------------------------------
    with st.sidebar.expander("🎲 Traffic Simulator (Testing)", expanded=False):
        attack_types = ["SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood", "Normal Traffic"]
        selected_attack = st.selectbox("Attack Type", attack_types, disabled=calibration_active)
        
        attack_intensity = st.slider("Intensity", 0.0, 1.0, 0.5, 0.1, disabled=calibration_active)
        packet_rate = st.slider("Rate (pkt/s)", 1, 50, 10, disabled=calibration_active)
        
        c3, c4 = st.columns(2)
        with c3:
            if st.button("Start Sim", disabled=st.session_state.simulation_running or calibration_active):
                start_traffic_simulator(selected_attack, attack_intensity, packet_rate)
        with c4:
            if st.button("Stop Sim", disabled=not st.session_state.simulation_running or calibration_active):
                stop_traffic_simulator()

    # System Controls (Bottom)
    st.sidebar.markdown("---")
    if st.sidebar.button("🗑️ Clear Logs", disabled=calibration_active):
        st.session_state.detection_results.clear()
        st.rerun()
    
    if st.sidebar.button("🔄 Full Reset", disabled=calibration_active):
        reset_system()
        st.rerun()

from streamlit.runtime.scriptrunner import add_script_run_ctx

def start_detection_system(interface, timeout):
    """Start the DDoS detection system"""
    # Check calibration requirement
    if not st.session_state.get('calibration_done', False) and not st.session_state.get('calibration_active', False):
        st.warning("⚠️ System Uncalibrated! Please run 'Calibrate System' first for accurate detection.")
        pass

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
        
        # Start ONLY Packet Capture in background thread (Producer)
        capture_thread = threading.Thread(
            target=st.session_state.packet_capture.start_capture_thread,
            daemon=True
        )
        add_script_run_ctx(capture_thread)
        capture_thread.start()
        
        # Note: We do NOT start a processing thread anymore. 
        # Processing happens in the main loop (Consumer).
        
        st.session_state.system_running = True
        st.success(f"✅ Detection system started on interface: {interface}")
        
    except Exception as e:
        st.error(f"❌ Failed to start detection system: {str(e)}")

def stop_detection_system():
    """Stop the DDoS detection system"""
    st.session_state.system_running = False
    if st.session_state.packet_capture:
        # This stops the producer thread
        st.session_state.packet_capture.stop_capture()
    st.warning("⚠️ Detection system stopped")

def start_traffic_simulator(attack_type, intensity, packet_rate):
    """Start traffic simulator"""
    try:
        # Configure simulator parameters
        st.session_state.traffic_simulator.set_attack_parameters(
            attack_type, intensity, packet_rate
        )
        
        # Start simulator (Producer)
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
    """
    Synchronous Batch Processor
    Processes a limited number of flows from the queue and returns.
    Called by the main loop.
    """
    processed_count = 0
    max_per_cycle = 500  # Process up to 500 flows per UI refresh for smooth real-time update
    
    try:
        while not st.session_state.flow_queue.empty() and processed_count < max_per_cycle:
            flow_data = st.session_state.flow_queue.get_nowait()
            
            # Perform model inference
            if st.session_state.get('calibration_active', False):
                # In calibration mode, we only run AutoEncoder to learn baseline
                is_anomaly, error = st.session_state.model_inference.autoencoder_predict(flow_data['features'])
                st.session_state.model_inference.baseline_errors.append(error)
                
                # Create a dummy "Calibration" result for the feed
                detection_result = {
                    'timestamp': flow_data['timestamp'],
                    'src_ip': flow_data['src_ip'],
                    'dst_ip': flow_data['dst_ip'],
                    'src_port': flow_data['src_port'],
                    'dst_port': flow_data['dst_port'],
                    'protocol': flow_data['protocol'],
                    'lucid_prediction': "Calibrating...",
                    'lucid_confidence': 0.0,
                    'autoencoder_anomaly': False, 
                    'reconstruction_error': error,
                    'final_prediction': "Calibrating",
                    'threat_level': "LOW",
                    'features': flow_data['features']
                }
            else:
                # Normal Inference
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
                    'features': flow_data['features']
                }
                
                # BLOCKING LOGIC
                if "Attack" in result['final_prediction']:
                    src_ip = flow_data['src_ip']
                    if result['threat_level'] == 'HIGH' or result['final_prediction'] == 'Attack':
                       st.session_state.prevention_system.block_ip(src_ip, reason=f"{result['final_prediction']} ({result['threat_level']})")
            
            # Add to results with size limit for performance
            st.session_state.detection_results.append(detection_result)
            if len(st.session_state.detection_results) > 2000:
                st.session_state.detection_results = st.session_state.detection_results[-1500:]
            
            # Update performance metrics
            st.session_state.performance_metrics['flows_analyzed'] += 1
            if detection_result['threat_level'] in ['HIGH', 'MEDIUM']:
                st.session_state.performance_metrics['threats_detected'] += 1
                
            processed_count += 1
            
    except queue.Empty:
        pass
    except Exception as e:
        print(f"ERROR in process_flows: {str(e)}")

if __name__ == "__main__":
    main()