import streamlit as st
import threading
import time
import queue
from dashboard import DDOSDetectionDashboard
from packet_capture import PacketCapture
from flow_manager import FlowManager
from model_inference import ModelInference
import os
import sys

# Configure Streamlit page
st.set_page_config(
    page_title="Real-Time DDoS Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    # Initialize session state
    if 'system_running' not in st.session_state:
        st.session_state.system_running = False
    if 'flow_queue' not in st.session_state:
        st.session_state.flow_queue = queue.Queue()
    if 'detection_results' not in st.session_state:
        st.session_state.detection_results = []
    if 'flow_manager' not in st.session_state:
        st.session_state.flow_manager = None
    if 'packet_capture' not in st.session_state:
        st.session_state.packet_capture = None
    if 'model_inference' not in st.session_state:
        st.session_state.model_inference = None

    # Check for required model files
    required_files = ['lucid.h5', 'lucid.pkl', 'auto.pth', 'auto.pkl']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        st.error(f"❌ Missing required model files: {', '.join(missing_files)}")
        st.info("Please upload the following files to the root directory:")
        for file in missing_files:
            st.write(f"- {file}")
        st.stop()

    # Initialize components
    if st.session_state.model_inference is None:
        try:
            st.session_state.model_inference = ModelInference()
            st.success("✅ Models loaded successfully!")
        except Exception as e:
            st.error(f"❌ Failed to load models: {str(e)}")
            st.stop()

    # Create dashboard
    dashboard = DDOSDetectionDashboard()
    
    # Sidebar controls
    st.sidebar.title("🛡️ DDoS Detection Control")
    
    # Network interface selection
    interfaces = ["lo", "eth0", "wlan0", "any"]  # Common interfaces
    selected_interface = st.sidebar.selectbox("Select Network Interface", interfaces)
    
    # Flow timeout setting
    flow_timeout = st.sidebar.slider("Flow Timeout (seconds)", 5, 30, 10)
    
    # System control buttons
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("🟢 Start Detection", disabled=st.session_state.system_running):
            start_detection_system(selected_interface, flow_timeout)
    
    with col2:
        if st.button("🔴 Stop Detection", disabled=not st.session_state.system_running):
            stop_detection_system()
    
    # System status
    status_color = "🟢" if st.session_state.system_running else "🔴"
    status_text = "ACTIVE" if st.session_state.system_running else "STOPPED"
    st.sidebar.markdown(f"**System Status:** {status_color} {status_text}")
    
    # Display dashboard
    dashboard.render(st.session_state.detection_results, st.session_state.system_running)
    
    # Auto-refresh when system is running
    if st.session_state.system_running:
        time.sleep(1)
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

def process_flows():
    """Process flows from the queue and perform inference"""
    while st.session_state.system_running:
        try:
            if not st.session_state.flow_queue.empty():
                flow_data = st.session_state.flow_queue.get_nowait()
                
                # Perform model inference
                result = st.session_state.model_inference.predict(flow_data['features'])
                
                # Add result to detection results
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
                    'threat_level': result['threat_level']
                }
                
                # Keep only last 1000 results for performance
                st.session_state.detection_results.append(detection_result)
                if len(st.session_state.detection_results) > 1000:
                    st.session_state.detection_results.pop(0)
            
            time.sleep(0.1)  # Small delay to prevent CPU overload
            
        except queue.Empty:
            time.sleep(0.1)
        except Exception as e:
            st.error(f"Error processing flows: {str(e)}")
            time.sleep(1)

if __name__ == "__main__":
    main()
