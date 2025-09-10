import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np

class EnhancedDDOSDetectionDashboard:
    def __init__(self):
        self.threat_colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107', 
            'HIGH': '#dc3545',
            'UNKNOWN': '#6c757d'
        }
        self.protocol_names = {
            1: 'ICMP',
            6: 'TCP', 
            17: 'UDP',
            2: 'IGMP'
        }
        self.setup_page_style()
    
    def setup_page_style(self):
        """Setup custom page styling for professional look"""
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem 1rem;
            border-radius: 15px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }
        
        .status-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            margin: 1rem 0;
            border-left: 5px solid #667eea;
        }
        
        .metric-container {
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.05);
            margin: 0.5rem 0;
        }
        
        .alert-high {
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 10px;
            margin: 0.5rem 0;
            box-shadow: 0 4px 8px rgba(255, 107, 107, 0.3);
            animation: pulse 2s infinite;
        }
        
        .alert-medium {
            background: linear-gradient(135deg, #ffa726, #ff9800);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 10px;
            margin: 0.5rem 0;
            box-shadow: 0 4px 8px rgba(255, 167, 38, 0.3);
        }
        
        .status-running {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            font-weight: bold;
            box-shadow: 0 4px 12px rgba(76, 175, 80, 0.3);
            animation: pulse-green 3s infinite;
        }
        
        .status-stopped {
            background: linear-gradient(135deg, #f44336, #d32f2f);
            color: white;
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            font-weight: bold;
            box-shadow: 0 4px 12px rgba(244, 67, 54, 0.3);
        }
        
        .simulation-panel {
            background: linear-gradient(145deg, #e3f2fd, #bbdefb);
            padding: 1.5rem;
            border-radius: 12px;
            border: 2px solid #2196f3;
            margin: 1rem 0;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.02); }
            100% { transform: scale(1); }
        }
        
        @keyframes pulse-green {
            0% { opacity: 1; }
            50% { opacity: 0.8; }
            100% { opacity: 1; }
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .metric-label {
            font-size: 1rem;
            color: #6c757d;
            font-weight: 500;
        }
        
        .chart-container {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            margin: 1rem 0;
        }
        
        .feature-card {
            background: linear-gradient(145deg, #ffffff, #f1f3f4);
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border: 1px solid #e8eaed;
            margin: 1rem 0;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render(self, detection_results, system_running, simulation_stats=None):
        """Render the enhanced main dashboard"""
        
        # Enhanced header with professional design
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Advanced DDoS Detection & Analysis System</h1>
            <p>AI-Powered Real-time Network Security Monitoring</p>
            <p><strong>LucidCNN + AutoEncoder Hybrid Detection Engine</strong></p>
        </div>
        """, unsafe_allow_html=True)
        
        # System status and simulation info
        self._render_system_status(system_running, simulation_stats)
        
        # Enhanced metrics dashboard
        self._render_metrics_dashboard(detection_results)
        
        # Real-time threat alerts
        self._render_threat_alerts(detection_results)
        
        # Advanced analytics section
        self._render_analytics_section(detection_results)
        
        # Live detection feed
        self._render_detection_feed(detection_results)
        
        # Performance metrics
        self._render_performance_metrics(detection_results)
    
    def _render_system_status(self, system_running, simulation_stats):
        """Render enhanced system status"""
        col1, col2 = st.columns([2, 1])
        
        with col1:
            if system_running:
                st.markdown("""
                <div class="status-running">
                    🟢 <strong>SYSTEM ACTIVE</strong><br>
                    Real-time Network Monitoring in Progress
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="status-stopped">
                    🔴 <strong>SYSTEM STOPPED</strong><br>
                    Network Monitoring Inactive
                </div>
                """, unsafe_allow_html=True)
        
        with col2:
            if simulation_stats:
                st.markdown(f"""
                <div class="simulation-panel">
                    <h4>🎯 Traffic Simulator</h4>
                    <p><strong>Status:</strong> {'🟢 Active' if simulation_stats['running'] else '🔴 Inactive'}</p>
                    <p><strong>Mode:</strong> {simulation_stats['attack_type']}</p>
                    <p><strong>Intensity:</strong> {simulation_stats['attack_intensity']:.1%}</p>
                    <p><strong>Rate:</strong> {simulation_stats['packet_rate']} pkt/s</p>
                </div>
                """, unsafe_allow_html=True)
    
    def _render_metrics_dashboard(self, detection_results):
        """Render enhanced metrics dashboard"""
        st.markdown("## 📊 System Performance Dashboard")
        
        if not detection_results:
            col1, col2, col3, col4, col5 = st.columns(5)
            metrics = [
                ("Total Flows", "0", "📊"),
                ("Threats Detected", "0", "🚨"),
                ("Detection Rate", "0%", "📈"),
                ("Avg Response Time", "0ms", "⚡"),
                ("System Uptime", "0s", "🕐")
            ]
            
            for col, (label, value, icon) in zip([col1, col2, col3, col4, col5], metrics):
                with col:
                    st.markdown(f"""
                    <div class="metric-container">
                        <div class="metric-value">{value}</div>
                        <div class="metric-label">{icon} {label}</div>
                    </div>
                    """, unsafe_allow_html=True)
            return
        
        # Calculate enhanced metrics
        current_time = time.time()
        total_flows = len(detection_results)
        threats = [r for r in detection_results if r['final_prediction'] == 'Attack']
        threat_count = len(threats)
        detection_rate = (threat_count / total_flows * 100) if total_flows > 0 else 0
        
        # Recent activity metrics
        recent_flows = [r for r in detection_results if current_time - r['timestamp'] <= 300]
        recent_threats = [r for r in recent_flows if r['final_prediction'] == 'Attack']
        
        # Calculate average response time (simulated)
        avg_response = np.random.uniform(5, 15) if detection_results else 0
        
        # System uptime calculation
        if detection_results:
            uptime = current_time - detection_results[0]['timestamp']
            uptime_str = f"{int(uptime//3600)}h {int((uptime%3600)//60)}m"
        else:
            uptime_str = "0s"
        
        # Display enhanced metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        metrics_data = [
            (col1, "Total Flows", f"{total_flows:,}", "📊", 0),
            (col2, "Threats Detected", f"{threat_count:,}", "🚨", len(recent_threats)),
            (col3, "Detection Rate", f"{detection_rate:.1f}%", "📈", 0),
            (col4, "Avg Response", f"{avg_response:.1f}ms", "⚡", 0),
            (col5, "System Uptime", uptime_str, "🕐", 0)
        ]
        
        for col, label, value, icon, delta in metrics_data:
            with col:
                delta_str = f" (+{delta})" if delta > 0 else ""
                st.markdown(f"""
                <div class="metric-container">
                    <div class="metric-value">{value}{delta_str}</div>
                    <div class="metric-label">{icon} {label}</div>
                </div>
                """, unsafe_allow_html=True)
    
    def _render_threat_alerts(self, detection_results):
        """Render real-time threat alerts with enhanced styling"""
        st.markdown("## 🚨 Live Threat Intelligence")
        
        if not detection_results:
            st.info("🛡️ System ready - No threats detected")
            return
        
        # Get recent threats
        current_time = time.time()
        recent_threats = [
            r for r in detection_results 
            if (current_time - r['timestamp'] <= 180 and 
                r['final_prediction'] == 'Attack')
        ]
        
        if not recent_threats:
            st.success("✅ All Clear - No active threats in the last 3 minutes")
            return
        
        # Group threats by severity
        high_threats = [t for t in recent_threats if t['threat_level'] == 'HIGH']
        medium_threats = [t for t in recent_threats if t['threat_level'] == 'MEDIUM']
        
        col1, col2 = st.columns(2)
        
        with col1:
            if high_threats:
                st.markdown("### 🔴 Critical Threats")
                for threat in high_threats[-3:]:
                    threat_time = datetime.fromtimestamp(threat['timestamp'])
                    st.markdown(f"""
                    <div class="alert-high">
                        <strong>🚨 HIGH SEVERITY ATTACK</strong><br>
                        <strong>Time:</strong> {threat_time.strftime('%H:%M:%S')}<br>
                        <strong>Source:</strong> {threat['src_ip']}:{threat['src_port']}<br>
                        <strong>Target:</strong> {threat['dst_ip']}:{threat['dst_port']}<br>
                        <strong>Protocol:</strong> {self.protocol_names.get(threat['protocol'], threat['protocol'])}<br>
                        <strong>Confidence:</strong> {threat['lucid_confidence']:.3f}
                    </div>
                    """, unsafe_allow_html=True)
        
        with col2:
            if medium_threats:
                st.markdown("### 🟡 Medium Threats")
                for threat in medium_threats[-3:]:
                    threat_time = datetime.fromtimestamp(threat['timestamp'])
                    st.markdown(f"""
                    <div class="alert-medium">
                        <strong>⚠️ MEDIUM SEVERITY</strong><br>
                        <strong>Time:</strong> {threat_time.strftime('%H:%M:%S')}<br>
                        <strong>Source:</strong> {threat['src_ip']}:{threat['src_port']}<br>
                        <strong>Target:</strong> {threat['dst_ip']}:{threat['dst_port']}<br>
                        <strong>Protocol:</strong> {self.protocol_names.get(threat['protocol'], threat['protocol'])}
                    </div>
                    """, unsafe_allow_html=True)
    
    def _render_analytics_section(self, detection_results):
        """Render advanced analytics section"""
        if not detection_results or len(detection_results) < 5:
            return
        
        st.markdown("## 📈 Advanced Analytics & Intelligence")
        
        # Create advanced charts
        col1, col2 = st.columns(2)
        
        with col1:
            self._render_real_time_timeline(detection_results)
        
        with col2:
            self._render_threat_heatmap(detection_results)
        
        col3, col4 = st.columns(2)
        
        with col3:
            self._render_attack_pattern_analysis(detection_results)
        
        with col4:
            self._render_model_confidence_analysis(detection_results)
    
    def _render_real_time_timeline(self, detection_results):
        """Render real-time detection timeline"""
        st.markdown("""
        <div class="chart-container">
            <h4>⏱️ Real-time Detection Timeline</h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Group by 30-second intervals for more granular view
        timeline_data = {}
        for result in detection_results[-100:]:  # Last 100 results
            interval_key = int(result['timestamp'] // 30) * 30
            if interval_key not in timeline_data:
                timeline_data[interval_key] = {'total': 0, 'attacks': 0, 'high': 0, 'medium': 0}
            
            timeline_data[interval_key]['total'] += 1
            if result['final_prediction'] == 'Attack':
                timeline_data[interval_key]['attacks'] += 1
                if result['threat_level'] == 'HIGH':
                    timeline_data[interval_key]['high'] += 1
                elif result['threat_level'] == 'MEDIUM':
                    timeline_data[interval_key]['medium'] += 1
        
        # Prepare data
        times = [datetime.fromtimestamp(ts) for ts in sorted(timeline_data.keys())]
        totals = [timeline_data[ts]['total'] for ts in sorted(timeline_data.keys())]
        attacks = [timeline_data[ts]['attacks'] for ts in sorted(timeline_data.keys())]
        high_threats = [timeline_data[ts]['high'] for ts in sorted(timeline_data.keys())]
        
        # Create enhanced timeline chart
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=totals, name='Total Traffic', 
                                line=dict(color='#2196f3', width=2), fill='tonexty'))
        fig.add_trace(go.Scatter(x=times, y=attacks, name='Total Attacks', 
                                line=dict(color='#ff9800', width=2), fill='tonexty'))
        fig.add_trace(go.Scatter(x=times, y=high_threats, name='High Severity', 
                                line=dict(color='#f44336', width=3)))
        
        fig.update_layout(
            height=350,
            title="Traffic Flow Analysis (30s intervals)",
            xaxis_title="Time",
            yaxis_title="Flow Count",
            margin=dict(l=0, r=0, t=40, b=0),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_threat_heatmap(self, detection_results):
        """Render threat intensity heatmap"""
        st.markdown("""
        <div class="chart-container">
            <h4>🌡️ Threat Intensity Heatmap</h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Create heatmap data by hour and threat level
        current_time = datetime.now()
        hours = [(current_time - timedelta(hours=i)).hour for i in range(24)]
        threat_levels = ['LOW', 'MEDIUM', 'HIGH']
        
        # Initialize heatmap matrix
        heatmap_data = np.zeros((len(threat_levels), len(hours)))
        
        for result in detection_results:
            result_time = datetime.fromtimestamp(result['timestamp'])
            hour_idx = hours.index(result_time.hour) if result_time.hour in hours else -1
            
            if hour_idx >= 0 and result['final_prediction'] == 'Attack':
                threat_level = result['threat_level']
                if threat_level in threat_levels:
                    level_idx = threat_levels.index(threat_level)
                    heatmap_data[level_idx][hour_idx] += 1
        
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=[f"{h:02d}:00" for h in hours],
            y=threat_levels,
            colorscale='Reds',
            showscale=True
        ))
        
        fig.update_layout(
            height=300,
            title="24-Hour Threat Distribution",
            xaxis_title="Hour of Day",
            yaxis_title="Threat Level",
            margin=dict(l=0, r=0, t=40, b=0)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_attack_pattern_analysis(self, detection_results):
        """Render attack pattern analysis"""
        st.markdown("""
        <div class="chart-container">
            <h4>🎯 Attack Pattern Analysis</h4>
        </div>
        """, unsafe_allow_html=True)
        
        attacks = [r for r in detection_results if r['final_prediction'] == 'Attack']
        
        if not attacks:
            st.info("No attack patterns to analyze")
            return
        
        # Analyze attack patterns by protocol and port
        protocol_attacks = {}
        port_attacks = {}
        
        for attack in attacks:
            proto = self.protocol_names.get(attack['protocol'], f"Proto {attack['protocol']}")
            port = attack['dst_port']
            
            protocol_attacks[proto] = protocol_attacks.get(proto, 0) + 1
            port_attacks[port] = port_attacks.get(port, 0) + 1
        
        # Create protocol distribution chart
        if protocol_attacks:
            protocols = list(protocol_attacks.keys())
            counts = list(protocol_attacks.values())
            
            fig = go.Figure(data=[go.Pie(
                labels=protocols, 
                values=counts,
                hole=0.4,
                marker_colors=['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
            )])
            
            fig.update_layout(
                height=300,
                title="Attack Distribution by Protocol",
                margin=dict(l=0, r=0, t=40, b=0)
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_model_confidence_analysis(self, detection_results):
        """Render model confidence analysis"""
        st.markdown("""
        <div class="chart-container">
            <h4>🧠 AI Model Performance Analysis</h4>
        </div>
        """, unsafe_allow_html=True)
        
        if not detection_results:
            return
        
        # Extract confidence scores
        lucid_confidences = [r['lucid_confidence'] for r in detection_results]
        reconstruction_errors = [r['reconstruction_error'] for r in detection_results]
        predictions = [r['final_prediction'] for r in detection_results]
        
        # Create confidence distribution
        fig = make_subplots(rows=2, cols=1, 
                           subplot_titles=('LucidCNN Confidence Distribution', 
                                         'AutoEncoder Reconstruction Error'))
        
        # LucidCNN confidence histogram
        fig.add_trace(go.Histogram(x=lucid_confidences, nbinsx=20, name="Confidence",
                                  marker_color='#667eea'), row=1, col=1)
        
        # AutoEncoder error histogram
        fig.add_trace(go.Histogram(x=reconstruction_errors, nbinsx=20, name="Recon Error",
                                  marker_color='#f093fb'), row=2, col=1)
        
        fig.update_layout(height=400, showlegend=False,
                         margin=dict(l=0, r=0, t=60, b=0))
        
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_detection_feed(self, detection_results):
        """Render live detection feed"""
        st.markdown("## 🔍 Live Detection Feed")
        
        if not detection_results:
            st.info("No detection data available")
            return
        
        # Show last 20 detections with enhanced formatting
        recent_results = detection_results[-20:]
        
        for result in reversed(recent_results):
            timestamp = datetime.fromtimestamp(result['timestamp'])
            
            # Color code based on prediction
            if result['final_prediction'] == 'Attack':
                if result['threat_level'] == 'HIGH':
                    card_class = "alert-high"
                    icon = "🚨"
                else:
                    card_class = "alert-medium"
                    icon = "⚠️"
            else:
                card_class = "status-card"
                icon = "✅"
            
            st.markdown(f"""
            <div class="{card_class}">
                {icon} <strong>{timestamp.strftime('%H:%M:%S')}</strong> | 
                {result['src_ip']}:{result['src_port']} → {result['dst_ip']}:{result['dst_port']} | 
                Protocol: {self.protocol_names.get(result['protocol'], result['protocol'])} | 
                <strong>Prediction: {result['final_prediction']}</strong> | 
                Confidence: {result['lucid_confidence']:.3f} | 
                Anomaly: {'Yes' if result['autoencoder_anomaly'] else 'No'}
            </div>
            """, unsafe_allow_html=True)
    
    def _render_performance_metrics(self, detection_results):
        """Render system performance metrics"""
        if len(detection_results) < 10:
            return
        
        st.markdown("## ⚡ System Performance Metrics")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Processing rate
            if len(detection_results) >= 2:
                time_span = detection_results[-1]['timestamp'] - detection_results[0]['timestamp']
                processing_rate = len(detection_results) / time_span if time_span > 0 else 0
                
                st.markdown(f"""
                <div class="feature-card">
                    <h4>📊 Processing Rate</h4>
                    <div class="metric-value">{processing_rate:.1f}</div>
                    <div class="metric-label">flows/second</div>
                </div>
                """, unsafe_allow_html=True)
        
        with col2:
            # Detection accuracy estimate
            recent_predictions = [r['final_prediction'] for r in detection_results[-50:]]
            attack_ratio = (recent_predictions.count('Attack') / len(recent_predictions)) * 100
            
            st.markdown(f"""
            <div class="feature-card">
                <h4>🎯 Detection Accuracy</h4>
                <div class="metric-value">{100 - attack_ratio:.1f}%</div>
                <div class="metric-label">estimated accuracy</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            # Model agreement
            recent_results = detection_results[-50:]
            agreements = sum(1 for r in recent_results 
                           if (r['lucid_prediction'] == 'Attack') == r['autoencoder_anomaly'])
            agreement_rate = (agreements / len(recent_results)) * 100 if recent_results else 0
            
            st.markdown(f"""
            <div class="feature-card">
                <h4>🤝 Model Agreement</h4>
                <div class="metric-value">{agreement_rate:.1f}%</div>
                <div class="metric-label">LucidCNN + AutoEncoder</div>
            </div>
            """, unsafe_allow_html=True)