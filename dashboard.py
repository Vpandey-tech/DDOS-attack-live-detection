import streamlit as st
import pandas as pd
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np

# === FIX STARTS HERE: New helper function to determine status text ===
def get_status_display_text(threat_level):
    """Returns the correct status text based on the threat level."""
    if threat_level == "HIGH":
        return "ATTACK"
    elif threat_level == "MEDIUM":
        return "SUSPICIOUS"
    else: # LOW
        return "NORMAL"
# =====================================================================

class DDOSDetectionDashboard:
    def __init__(self):
        self.threat_colors = {
            'LOW': '#28a745',    # Green
            'MEDIUM': '#ffc107', # Yellow
            'HIGH': '#dc3545',   # Red
            'UNKNOWN': '#6c757d'
        }
        
        if 'packet_count' not in st.session_state:
            st.session_state.packet_count = 0
        if 'operation_mode' not in st.session_state:
            st.session_state.operation_mode = 'Live Monitoring'
        self.setup_page_style()

    def setup_page_style(self):
        """Setup custom page styling"""
        # ... (rest of the function is unchanged) ...
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .metric-card {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #667eea;
        }
        
        .threat-high {
            background: linear-gradient(90deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin: 0.5rem 0;
        }
        
        .threat-medium {
            background: linear-gradient(90deg, #ffa726, #ff9800);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin: 0.5rem 0;
        }
        
        .status-active {
            background: linear-gradient(90deg, #4CAF50, #45a049);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        
        .status-inactive {
            background: linear-gradient(90deg, #f44336, #d32f2f);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        
        .chart-container {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin: 1rem 0;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render_live_monitoring(self, detection_results, system_running, current_threshold="N/A"):
        # === THIS IS THE UPDATED FUNCTION ===
        st.markdown("""
        <div class="main-header">
            <h1>🔍 Live Traffic Monitoring</h1>
            <p>Real-time network analysis with adaptive threat detection</p>
        </div>
        """, unsafe_allow_html=True)
        
        self._render_enhanced_status(system_running)
        # === MODIFIED: Pass the threshold down to the metrics display ===
        self._render_enhanced_metrics(detection_results, current_threshold)
        # ===============================================================
        self._render_enhanced_alerts(detection_results)
        self._render_enhanced_detection_table(detection_results)
        self._render_advanced_analytics(detection_results)
        self._render_advanced_visualizations(detection_results)

    

    def _render_enhanced_detection_table(self, detection_results):
        """Render enhanced detection results table with packet type and status indicators"""
        st.subheader("🔍 Live Detection Results")
        
        if not detection_results:
            st.info("💡 **No detection results yet** - Waiting for traffic...")
            return
        
        # Strictly show the last 50 results
        recent_results = detection_results[-50:]
        
        table_data = []
        for result in reversed(recent_results):
            # Determine status display
            status = result.get('status', 'ANALYZED')
            threat = result['threat_level']
            
            # Formatting logic
            row = {
                'Time': datetime.fromtimestamp(result['timestamp']).strftime('%H:%M:%S'),
                'Source': f"{result['src_ip']}:{result['src_port']}",
                'Destination': f"{result['dst_ip']}:{result['dst_port']}",
                'Protocol': result['protocol'],
                'Threat Level': threat,
                'Status': status,
                'Confidence': f"{result['lucid_confidence']:.2f}",
                'Score': f"{result['reconstruction_error']:.2f}"
            }
            table_data.append(row)
        
        df = pd.DataFrame(table_data)
        
        # Color styling
        def highlight_row(row):
            styles = [''] * len(row)
            if row['Status'] == 'BLOCKED':
                return ['background-color: #ffcdd2; color: #b71c1c; font-weight: bold'] * len(row)
            elif row['Status'] == 'FLAGGED':
                return ['background-color: #fff9c4; color: #f57f17'] * len(row)
            elif row['Threat Level'] == 'HIGH':
                return ['background-color: #ff8a80; color: white'] * len(row)
            return styles

        st.dataframe(
            df.style.apply(highlight_row, axis=1),
            width="stretch", 
            height=400,
            hide_index=True
        )

    # ... (all other functions in the class remain unchanged) ...
    
    def render_testing_simulation(self, simulation_results, simulation_stats=None):
        """Render the Testing & Simulation dashboard"""
        
        # Testing header
        st.markdown("""
        <div class="main-header">
            <h1>🧪 Testing & Simulation</h1>
            <p>Controlled testing environment for DDoS attack simulation</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Set operation mode
        st.session_state.operation_mode = 'Simulation'
        
        # Simulation status
        self._render_simulation_status(simulation_stats)
        
        # Simulation metrics
        self._render_simulation_metrics(simulation_results, simulation_stats)
        
        # Simulation results
        if simulation_results:
            self._render_enhanced_detection_table(simulation_results)
            self._render_advanced_visualizations(simulation_results)
    
    def render(self, detection_results, system_running, simulation_stats=None):
        """Render the main dashboard (backward compatibility)"""
        
        # Enhanced header
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Advanced DDoS Detection & Analysis System</h1>
            <p>Real-time network traffic monitoring with AI-powered threat detection</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Enhanced system status
        self._render_enhanced_status(system_running, simulation_stats)
        
        # Enhanced metrics overview
        self._render_enhanced_metrics(detection_results)
        
        # Real-time alerts with animations
        self._render_enhanced_alerts(detection_results)
        
        # Advanced analytics section
        self._render_advanced_analytics(detection_results)
        
        # Enhanced detection table
        self._render_enhanced_detection_table(detection_results)
        
        # Advanced visualizations
        self._render_advanced_visualizations(detection_results)
    
    def _render_simulation_status(self, simulation_stats):
        """Render simulation status section"""
        st.subheader("🧪 Simulation Status")
        
        if simulation_stats:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if simulation_stats.get('running', False):
                    st.markdown('<div class="status-active">🟢 SIMULATION RUNNING</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="status-inactive">🔴 SIMULATION STOPPED</div>', unsafe_allow_html=True)
            
            with col2:
                attack_type = simulation_stats.get('attack_type', 'None')
                st.markdown(f'<div class="status-active">🎯 {attack_type.upper()}</div>', unsafe_allow_html=True)
            
            with col3:
                intensity = simulation_stats.get('intensity', 0)
                st.markdown(f'<div class="status-active">⚡ {intensity}% INTENSITY</div>', unsafe_allow_html=True)
        else:
            st.info("No simulation running - Use controls below to start testing")
    
    def _render_simulation_metrics(self, simulation_results, simulation_stats):
        """Render simulation-specific metrics"""
        st.subheader("📊 Simulation Metrics")
        
        if not simulation_results:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Simulated Packets", "0")
            with col2:
                st.metric("Detected Attacks", "0")
            with col3:
                st.metric("Detection Accuracy", "0%")
            with col4:
                st.metric("False Positives", "0")
            return
        
        # Calculate simulation metrics
        total_packets = len(simulation_results)
        detected_attacks = len([r for r in simulation_results if r['final_prediction'] == 'Attack'])
        
        # If we know the simulation type, calculate accuracy
        accuracy = "N/A"
        false_positives = 0
        
        if simulation_stats and simulation_stats.get('attack_type') != 'Normal Traffic':
            # For attack simulations, we expect most to be detected as attacks
            expected_attacks = int(total_packets * 0.8)  # Expect 80% to be attacks
            accuracy = f"{(detected_attacks / expected_attacks * 100):.1f}%" if expected_attacks > 0 else "N/A"
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Simulated Packets", f"{total_packets:,}")
        
        with col2:
            st.metric("Detected Attacks", f"{detected_attacks:,}")
        
        with col3:
            st.metric("Detection Accuracy", accuracy)
        
        with col4:
            normal_detected = total_packets - detected_attacks
            st.metric("Normal Traffic", f"{normal_detected:,}")
    
    def _render_metrics(self, detection_results):
        """Render key metrics"""
        st.subheader("📊 System Metrics")
        
        if not detection_results:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Flows", "0")
            with col2:
                st.metric("Threats Detected", "0")
            with col3:
                st.metric("Detection Rate", "0%")
            with col4:
                st.metric("Last Update", "N/A")
            return
        
        # Calculate metrics
        total_flows = len(detection_results)
        threats = [r for r in detection_results if r['final_prediction'] == 'Attack']
        threat_count = len(threats)
        detection_rate = (threat_count / total_flows * 100) if total_flows > 0 else 0
        
        # Recent activity (last 5 minutes)
        current_time = time.time()
        recent_flows = [r for r in detection_results if current_time - r['timestamp'] <= 300]
        recent_threats = [r for r in recent_flows if current_time - r['timestamp'] <= 300 and r['final_prediction'] == 'Attack']
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Flows", f"{total_flows:,}")
        
        with col2:
            st.metric("Threats Detected", f"{threat_count:,}", 
                     delta=f"+{len(recent_threats)}" if recent_threats else "0")
        
        with col3:
            st.metric("Detection Rate", f"{detection_rate:.1f}%")
        
        with col4:
            if detection_results:
                last_update = datetime.fromtimestamp(detection_results[-1]['timestamp'])
                st.metric("Last Update", last_update.strftime("%H:%M:%S"))
            else:
                st.metric("Last Update", "N/A")
    
    def _render_alerts(self, detection_results):
        """Render real-time alerts for threats"""
        st.subheader("🚨 Real-Time Alerts")
        
        if not detection_results:
            st.info("No alerts - System ready for monitoring")
            return
        
        # Get recent high-priority threats (last 2 minutes)
        current_time = time.time()
        recent_threats = [
            r for r in detection_results 
            if (current_time - r['timestamp'] <= 120 and 
                r['final_prediction'] == 'Attack' and 
                r['threat_level'] in ['HIGH', 'MEDIUM'])
        ]
        
        if not recent_threats:
            st.success("✅ No active threats detected")
            return
        
        # Display recent threats
        for threat in recent_threats[-5:]:  # Show last 5 threats
            threat_time = datetime.fromtimestamp(threat['timestamp'])
            
            # Color code based on threat level
            if threat['threat_level'] == 'HIGH':
                alert_type = "error"
            elif threat['threat_level'] == 'MEDIUM':
                alert_type = "warning"
            else:
                alert_type = "info"
            
            getattr(st, alert_type)(
                f"**{threat['threat_level']} THREAT** at {threat_time.strftime('%H:%M:%S')} - "
                f"{threat['src_ip']}:{threat['src_port']} → {threat['dst_ip']}:{threat['dst_port']} "
                f"(Protocol: {threat['protocol']})"
            )
    
    def _render_detection_table_old(self, detection_results):
        """Render detection results table (kept for reference)"""
        st.subheader("🔍 Recent Detection Results")
        
        if not detection_results:
            st.info("No detection results available")
            return
        
        # Prepare data for table (last 50 results)
        recent_results = detection_results[-50:]
        
        table_data = []
        for result in reversed(recent_results):  # Show newest first
            table_data.append({
                'Timestamp': datetime.fromtimestamp(result['timestamp']).strftime('%H:%M:%S'),
                'Source IP': result['src_ip'],
                'Dest IP': result['dst_ip'],
                'Source Port': result['src_port'],
                'Dest Port': result['dst_port'],
                'Protocol': result['protocol'],
                'LucidCNN': result['lucid_prediction'],
                'Confidence': f"{result['lucid_confidence']:.3f}",
                'Anomaly': '✓' if result['autoencoder_anomaly'] else '✗',
                'Recon Error': f"{result['reconstruction_error']:.4f}",
                'Final Prediction': result['final_prediction'],
                'Threat Level': result['threat_level']
            })
        
        df = pd.DataFrame(table_data)
        
        # Style the dataframe
        def style_prediction(val):
            if val == 'Attack':
                return 'background-color: #ffebee'
            elif val == 'Benign':
                return 'background-color: #e8f5e8'
            return ''
        
        def style_threat_level(val):
            color = self.threat_colors.get(val, '#ffffff')
            return f'background-color: {color}; color: white; font-weight: bold'
        
        styled_df = df.style.applymap(style_prediction, subset=['Final Prediction']) \
                           .applymap(style_threat_level, subset=['Threat Level'])
        
        st.dataframe(styled_df, width="stretch")
    
    def _render_visualizations(self, detection_results):
        """Render data visualizations"""
        if not detection_results or len(detection_results) < 2:
            return
        
        st.subheader("📈 Analytics Dashboard")
        
        # Create two columns for charts
        col1, col2 = st.columns(2)
        
        with col1:
            self._render_threat_timeline(detection_results)
        
        with col2:
            self._render_threat_distribution(detection_results)
        
        # Protocol and IP analysis
        col3, col4 = st.columns(2)
        
        with col3:
            self._render_protocol_analysis(detection_results)
        
        with col4:
            self._render_top_sources(detection_results)
    
    def _render_threat_timeline(self, detection_results):
        """Render threat detection timeline"""
        st.write("**Threat Detection Timeline**")
        
        # Group by time intervals (1-minute buckets)
        timeline_data = {}
        for result in detection_results:
            # Round to nearest minute
            minute_key = int(result['timestamp'] // 60) * 60
            if minute_key not in timeline_data:
                timeline_data[minute_key] = {'total': 0, 'threats': 0}
            
            timeline_data[minute_key]['total'] += 1
            if result['final_prediction'] == 'Attack':
                timeline_data[minute_key]['threats'] += 1
        
        # Prepare chart data
        times = []
        totals = []
        threats = []
        
        for timestamp in sorted(timeline_data.keys()):
            times.append(datetime.fromtimestamp(timestamp))
            totals.append(timeline_data[timestamp]['total'])
            threats.append(timeline_data[timestamp]['threats'])
        
        # Create chart
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=totals, name='Total Flows', line=dict(color='blue')))
        fig.add_trace(go.Scatter(x=times, y=threats, name='Threats', line=dict(color='red')))
        
        fig.update_layout(
            height=300,
            xaxis_title="Time",
            yaxis_title="Count",
            margin=dict(l=0, r=0, t=30, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_threat_distribution(self, detection_results):
        """Render threat level distribution"""
        st.write("**Threat Level Distribution**")
        
        # Count threat levels
        threat_counts = {}
        for result in detection_results:
            level = result['threat_level']
            threat_counts[level] = threat_counts.get(level, 0) + 1
        
        # Create pie chart
        labels = list(threat_counts.keys())
        values = list(threat_counts.values())
        colors = [self.threat_colors.get(label, '#cccccc') for label in labels]
        
        fig = go.Figure(data=[go.Pie(labels=labels, values=values, marker_colors=colors)])
        fig.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0))
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_protocol_analysis(self, detection_results):
        """Render protocol analysis"""
        st.write("**Protocol Analysis**")
        
        protocol_data = {}
        for result in detection_results:
            proto = result['protocol']
            if proto not in protocol_data:
                protocol_data[proto] = {'total': 0, 'attacks': 0}
            
            protocol_data[proto]['total'] += 1
            if result['final_prediction'] == 'Attack':
                protocol_data[proto]['attacks'] += 1
        
        # Prepare chart data
        protocols = list(protocol_data.keys())
        totals = [protocol_data[p]['total'] for p in protocols]
        attacks = [protocol_data[p]['attacks'] for p in protocols]
        
        fig = go.Figure(data=[
            go.Bar(name='Total', x=protocols, y=totals),
            go.Bar(name='Attacks', x=protocols, y=attacks)
        ])
        
        fig.update_layout(
            height=300,
            barmode='group',
            xaxis_title="Protocol",
            yaxis_title="Count",
            margin=dict(l=0, r=0, t=30, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_top_sources(self, detection_results):
        """Render top source IPs with threats"""
        st.write("**Top Threat Sources**")
        
        # Count threats by source IP
        source_threats = {}
        for result in detection_results:
            if result['final_prediction'] == 'Attack':
                src_ip = result['src_ip']
                source_threats[src_ip] = source_threats.get(src_ip, 0) + 1
        
        if not source_threats:
            st.info("No threat sources detected")
            return
        
        # Get top 10 sources
        top_sources = sorted(source_threats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        if top_sources:
            source_ips = [item[0] for item in top_sources]
            threat_counts = [item[1] for item in top_sources]
            
            fig = go.Figure(data=[go.Bar(x=threat_counts, y=source_ips, orientation='h')])
            fig.update_layout(
                height=300,
                xaxis_title="Threat Count",
                yaxis_title="Source IP",
                margin=dict(l=0, r=0, t=30, b=0)
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat sources to display")
    
    def _render_enhanced_status(self, system_running, simulation_stats=None):
        """Render enhanced system status with live traffic indicators"""
        st.subheader("🔧 System Status")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if system_running:
                st.markdown('<div class="status-active">🟢 SYSTEM ACTIVE</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="status-inactive">🔴 SYSTEM OFFLINE</div>', unsafe_allow_html=True)
        
        with col2:
            # Live packet indicator
            if 'packet_count' in st.session_state and st.session_state.packet_count > 0:
                st.markdown('<div class="status-active">📡 RECEIVING LIVE TRAFFIC</div>', unsafe_allow_html=True)
                st.caption(f"Packets captured: {st.session_state.packet_count}")
            else:
                st.markdown('<div class="status-inactive">📡 NO LIVE TRAFFIC</div>', unsafe_allow_html=True)
        
        with col3:
            # Mode indicator
            current_mode = st.session_state.get('operation_mode', 'Live Monitoring')
            if current_mode == 'Simulation':
                st.markdown('<div class="status-active">🧪 SIMULATION MODE</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="status-active">🔍 LIVE MONITORING</div>', unsafe_allow_html=True)
    
    def _render_enhanced_metrics(self, detection_results, current_threshold):
        # === THIS IS THE UPDATED FUNCTION ===
        st.subheader("📊 System Metrics")
        
        if not detection_results:
            # === MODIFIED: Added a placeholder for the new column ===
            col1, col2, col3, col4, col5, col6 = st.columns(6)
            # ========================================================
            with col1:
                st.metric("Total Flows", "0")
            with col2:
                st.metric("Normal Packets", "0", help="Benign traffic detected")
            with col3:
                st.metric("Attack Packets", "0", help="Malicious traffic detected")
            with col4:
                st.metric("Detection Rate", "0%")
            with col5:
                st.metric("Last Update", "N/A")
            # === NEW: Placeholder for Adaptive Threshold when no data is present ===
            with col6:
                st.metric("Adaptive Threshold", "N/A")
            # =====================================================================
            return
        
        # Calculate enhanced metrics
        total_flows = len(detection_results)
        attacks = [r for r in detection_results if r['final_prediction'] == 'Attack']
        normals = [r for r in detection_results if r['final_prediction'] == 'Benign']
        attack_count = len(attacks)
        normal_count = len(normals)
        detection_rate = (attack_count / total_flows * 100) if total_flows > 0 else 0
        
        # Recent activity indicators
        current_time = time.time()
        recent_flows = [r for r in detection_results if current_time - r['timestamp'] <= 60]  # Last minute
        recent_attacks = [r for r in recent_flows if current_time - r['timestamp'] <= 60 and r['final_prediction'] == 'Attack']
        recent_normals = [r for r in recent_flows if current_time - r['timestamp'] <= 60 and r['final_prediction'] == 'Benign']
        
        # === MODIFIED: Changed from 5 to 6 columns to make space ===
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        # ===========================================================
        
        with col1:
            st.metric("Total Flows", f"{total_flows:,}")
        
        with col2:
            normal_delta = f"+{len(recent_normals)}" if recent_normals else "0"
            st.metric("✅ Normal Packets", f"{normal_count:,}", 
                     delta=normal_delta, delta_color="normal",
                     help="Benign traffic - no threats detected")
        
        with col3:
            attack_delta = f"+{len(recent_attacks)}" if recent_attacks else "0"
            st.metric("🚨 Attack Packets", f"{attack_count:,}", 
                     delta=attack_delta, delta_color="inverse",
                     help="Malicious traffic detected by AI models")
        
        with col4:
            st.metric("Detection Rate", f"{detection_rate:.1f}%")
        
        with col5:
            if detection_results:
                last_update = datetime.fromtimestamp(detection_results[-1]['timestamp'])
                st.metric("Last Update", last_update.strftime("%H:%M:%S"))
            else:
                st.metric("Last Update", "N/A")
        
        # === NEW: This new column displays the live adaptive threshold ===
        with col6:
            threshold_val = f"{current_threshold:.2f}" if isinstance(current_threshold, float) else current_threshold
            st.metric("Adaptive Threshold", threshold_val, help="The current anomaly score needed to trigger an alert. This value adapts to your network's normal behavior.")
    
    def _render_enhanced_alerts(self, detection_results):
        """Render enhanced real-time alerts with packet type indicators"""
        st.subheader("🚨 Real-Time Alerts & Packet Status")
        
        # Real-time packet status indicators
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**📡 Live Packet Reception Status**")
            if not detection_results:
                st.info("🔍 **Waiting for packets...** System is ready to analyze network traffic")
                return
            
            # Recent packet analysis (last 30 seconds)
            current_time = time.time()
            recent_packets = [r for r in detection_results if current_time - r['timestamp'] <= 30]
            
            if recent_packets:
                recent_attacks = [r for r in recent_packets if r['final_prediction'] == 'Attack']
                recent_normals = [r for r in recent_packets if r['final_prediction'] == 'Benign']
                
                if recent_normals:
                    st.success(f"✅ **{len(recent_normals)} Normal packets** received (last 30s)")
                
                if recent_attacks:
                    st.error(f"🚨 **{len(recent_attacks)} Attack packets** detected (last 30s)")
                    
                    # Show latest attack details
                    latest_attack = recent_attacks[-1]
                    attack_time = datetime.fromtimestamp(latest_attack['timestamp'])
                    st.warning(
                        f"⚠️ **Latest Threat:** {latest_attack['src_ip']} → {latest_attack['dst_ip']} "
                        f"at {attack_time.strftime('%H:%M:%S')} "
                        f"({latest_attack['threat_level']} priority)"
                    )
            else:
                st.info("📡 **No recent packets** (last 30 seconds)")
        
        with col2:
            st.markdown("**🛡️ Threat Analysis**")
            
            # Get recent high-priority threats (last 2 minutes)
            recent_threats = [
                r for r in detection_results 
                if (current_time - r['timestamp'] <= 120 and 
                    r['final_prediction'] == 'Attack' and 
                    r['threat_level'] in ['HIGH', 'MEDIUM'])
            ]
            
            if not recent_threats:
                st.success("✅ **No active threats** - All traffic appears normal")
            else:
                # Display recent threats with enhanced formatting
                for threat in recent_threats[-3:]:  # Show last 3 threats
                    threat_time = datetime.fromtimestamp(threat['timestamp'])
                    
                    if threat['threat_level'] == 'HIGH':
                        st.markdown(
                            f'<div class="threat-high">'
                            f'🔥 <strong>HIGH THREAT</strong> at {threat_time.strftime("%H:%M:%S")}<br>'
                            f'{threat["src_ip"]}:{threat["src_port"]} → {threat["dst_ip"]}:{threat["dst_port"]}'
                            f'</div>', 
                            unsafe_allow_html=True
                        )
                    elif threat['threat_level'] == 'MEDIUM':
                        st.markdown(
                            f'<div class="threat-medium">'
                            f'⚠️ <strong>MEDIUM THREAT</strong> at {threat_time.strftime("%H:%M:%S")}<br>'
                            f'{threat["src_ip"]}:{threat["src_port"]} → {threat["dst_ip"]}:{threat["dst_port"]}'
                            f'</div>', 
                            unsafe_allow_html=True
                        )
    
    def _render_advanced_analytics(self, detection_results):
        """Render advanced analytics section"""
        if not detection_results or len(detection_results) < 2:
            return
        
        st.subheader("📈 Advanced Analytics")
        
        # Create analytics tabs
        tab1, tab2, tab3 = st.tabs(["📊 Traffic Analysis", "🔍 Threat Intelligence", "⚡ Performance Metrics"])
        
        with tab1:
            self._render_traffic_analysis(detection_results)
        
        with tab2:
            self._render_threat_intelligence(detection_results)
        
        with tab3:
            self._render_performance_metrics(detection_results)
    
    def _render_advanced_visualizations(self, detection_results):
        """Render advanced visualization charts"""
        if not detection_results or len(detection_results) < 2:
            return
        
        st.subheader("📈 Advanced Visualizations")
        
        # Create two columns for charts
        col1, col2 = st.columns(2)
        
        with col1:
            self._render_threat_timeline(detection_results)
        
        with col2:
            self._render_threat_distribution(detection_results)
        
        # Protocol and IP analysis
        col3, col4 = st.columns(2)
        
        with col3:
            self._render_protocol_analysis(detection_results)
        
        with col4:
            self._render_top_sources(detection_results)
    
    def _render_traffic_analysis(self, detection_results):
        """Render traffic analysis charts"""
        st.write("**Traffic Flow Analysis**")
        
        # Traffic volume over time
        timeline_data = {}
        for result in detection_results:
            minute_key = int(result['timestamp'] // 60) * 60
            if minute_key not in timeline_data:
                timeline_data[minute_key] = {'total': 0, 'normal': 0, 'attack': 0}
            
            timeline_data[minute_key]['total'] += 1
            if result['final_prediction'] == 'Attack':
                timeline_data[minute_key]['attack'] += 1
            else:
                timeline_data[minute_key]['normal'] += 1
        
        times = [datetime.fromtimestamp(t) for t in sorted(timeline_data.keys())]
        normals = [timeline_data[t]['normal'] for t in sorted(timeline_data.keys())]
        attacks = [timeline_data[t]['attack'] for t in sorted(timeline_data.keys())]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=normals, name='Normal Traffic', 
                                line=dict(color='green'), fill='tonexty'))
        fig.add_trace(go.Scatter(x=times, y=attacks, name='Attack Traffic', 
                                line=dict(color='red'), fill='tozeroy'))
        
        fig.update_layout(
            height=300,
            xaxis_title="Time",
            yaxis_title="Packet Count",
            margin=dict(l=0, r=0, t=30, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_threat_intelligence(self, detection_results):
        """Render threat intelligence analysis"""
        st.write("**Threat Intelligence Dashboard**")
        
        # Threat sources analysis
        threat_sources = {}
        for result in detection_results:
            if result['final_prediction'] == 'Attack':
                src = result['src_ip']
                if src not in threat_sources:
                    threat_sources[src] = {'count': 0, 'latest': result['timestamp']}
                threat_sources[src]['count'] += 1
                threat_sources[src]['latest'] = max(threat_sources[src]['latest'], result['timestamp'])
        
        if threat_sources:
            # Create threat intelligence table
            threat_data = []
            for ip, data in sorted(threat_sources.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
                threat_data.append({
                    'Source IP': ip,
                    'Attack Count': data['count'],
                    'Latest Activity': datetime.fromtimestamp(data['latest']).strftime('%H:%M:%S'),
                    'Risk Level': 'HIGH' if data['count'] > 10 else 'MEDIUM' if data['count'] > 5 else 'LOW'
                })
            
            st.dataframe(pd.DataFrame(threat_data), width="stretch")
        else:
            st.info("No threat sources identified")
    
    def _render_performance_metrics(self, detection_results):
        """Render system performance metrics"""
        st.write("**System Performance Metrics**")
        
        # Calculate performance metrics
        if detection_results:
            processing_times = []
            for i in range(1, len(detection_results)):
                time_diff = detection_results[i]['timestamp'] - detection_results[i-1]['timestamp']
                if time_diff > 0:
                    processing_times.append(time_diff)
            
            if processing_times:
                avg_processing = np.mean(processing_times)
                max_processing = max(processing_times)
                min_processing = min(processing_times)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Avg Processing Time", f"{avg_processing:.3f}s")
                with col2:
                    st.metric("Max Processing Time", f"{max_processing:.3f}s")
                with col3:
                    st.metric("Min Processing Time", f"{min_processing:.3f}s")
                
                # Processing time timeline
                times = [datetime.fromtimestamp(detection_results[i]['timestamp']) 
                        for i in range(1, len(detection_results))]
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=times, y=processing_times, 
                                       name='Processing Time', line=dict(color='blue')))
                fig.update_layout(
                    height=200,
                    xaxis_title="Time",
                    yaxis_title="Processing Time (s)",
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No performance data available")

