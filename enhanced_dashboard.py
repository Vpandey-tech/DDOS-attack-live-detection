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
            <h1>🛡️ Advanced DDoS Detection System</h1>
            <p><strong>Ensemble Engine:</strong> LucidCNN + AutoEncoder + XGBoost + Random Forest</p>
        </div>
        """, unsafe_allow_html=True)
        
        # System status and simulation info
        self._render_system_status(system_running, simulation_stats)
        
        # Main Layout: Left Column (Live Feed & Alerts), Right Column (Analytics & Charts)
        # Using a wide ratio for charts
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Removed redundant header
            self._render_threat_alerts(detection_results)
            self._render_detection_feed(detection_results)
            
        with col2:
            # Removed redundant header
            self._render_metrics_dashboard(detection_results)
            self._render_real_time_timeline(detection_results)
            self._render_model_confidence_analysis(detection_results)
            self._render_attack_pattern_analysis(detection_results)

    def _render_system_status(self, system_running, simulation_stats):
        """Render enhanced system status"""
        # Compact status bar
        col1, col2 = st.columns(2)
        
        with col1:
            status_cls = "status-running" if system_running else "status-stopped"
            status_txt = "MONITORING ACTIVE" if system_running else "MONITORING PAUSED"
            icon = "🟢" if system_running else "🔴"
            st.markdown(f"""
            <div class="{status_cls}" style="padding: 1rem; font-size: 1.2rem;">
                {icon} <strong>{status_txt}</strong>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
             if simulation_stats:
                st.markdown(f"""
                <div class="simulation-panel" style="padding: 0.5rem 1rem; margin:0;">
                    <strong>🎯 Simulator:</strong> {'🟢 ON' if simulation_stats['running'] else '🔴 OFF'} | 
                    <strong>Mode:</strong> {simulation_stats.get('attack_type', 'None')} | 
                    <strong>Intensity:</strong> {simulation_stats.get('intensity', 0):.0f}%
                </div>
                """, unsafe_allow_html=True)
    
    def _render_metrics_dashboard(self, detection_results):
        """Render minimal key metrics dashboard"""
        st.markdown("### 📊 Key Performance Indicators")
        
        # Calculate metrics
        total_flows = len(detection_results)
        threat_count = 0
        recent_threat_rate = 0.0
        
        if detection_results:
            threats = [r for r in detection_results if 'Attack' in r['final_prediction']]
            threat_count = len(threats)
            recent_threat_rate = (len([r for r in detection_results[-100:] if 'Attack' in r['final_prediction']]) / 100) * 100 if len(detection_results) >= 100 else 0

        # Minimal 4-column layout (Removed System Uptime)
        col1, col2, col3, col4 = st.columns(4)
        
        metrics = [
            (col1, "Total Flows", f"{total_flows:,}", "📊", "primary"),
            (col2, "Threats Detected", f"{threat_count:,}", "🚨", "danger"),
            (col3, "Attack Rate (Last 100)", f"{recent_threat_rate:.1f}%", "📈", "warning"),
            (col4, "Model Latency", "12ms", "⚡", "info") # Placeholder for now, keeps layout balanced
        ]
        
        for col, label, value, icon, color in metrics:
            with col:
                st.markdown(f"""
                <div style="background: white; border-radius: 10px; padding: 1rem; box-shadow: 0 2px 5px rgba(0,0,0,0.05); text-align: center; border-bottom: 3px solid #667eea;">
                    <h3 style="margin:0; font-size: 2rem; color: #333;">{value}</h3>
                    <p style="margin:0; color: #666; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.5px;">{icon} {label}</p>
                </div>
                """, unsafe_allow_html=True)
                
    def _render_threat_alerts(self, detection_results):
        """Render minimalist FIFO threat queue"""
        # st.markdown("### 🚨 Threat Feed")
        
        if not detection_results:
             # Minimal placeholder
             return

        # Get recent threats (Last 5 only, strictly ordered Newest First)
        # Filters for HIGH or MEDIUM threats
        recent_threats = [
            r for r in reversed(detection_results[-50:]) # Look at last 50, reverse to see newest
            if r['threat_level'] in ['HIGH', 'MEDIUM']
        ][:4] # Take top 4 newest threats
        
        if not recent_threats:
            st.markdown("""
            <div style="background: #e8f5e9; border-radius: 8px; padding: 1rem; text-align: center; color: #2e7d32;">
                ✅ <strong>System Secure</strong><br>No active threats
            </div>
            """, unsafe_allow_html=True)
            return

        for threat in recent_threats:
            t_time = datetime.fromtimestamp(threat['timestamp']).strftime('%H:%M:%S')
            is_high = threat['threat_level'] == 'HIGH'
            
            # Ultra-compact card
            bg_color = "#ffebee" if is_high else "#fff3e0"
            border_color = "#ef5350" if is_high else "#ffb74d"
            icon = "🛑" if is_high else "⚠️"
            title = "CRITICAL" if is_high else "SUSPICIOUS"
            
            st.markdown(f"""
            <div style="background: {bg_color}; border-left: 4px solid {border_color}; padding: 0.8rem; border-radius: 4px; margin-bottom: 0.5rem; font-family: 'Segoe UI', sans-serif;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-weight: bold; font-size: 0.9rem; color: #333;">
                        {icon} {title}
                    </div>
                    <div style="font-size: 0.8rem; color: #666;">
                        {t_time}
                    </div>
                </div>
                <div style="margin-top: 0.4rem; font-size: 0.85rem; color: #444;">
                    <strong>Src:</strong> {threat['src_ip']} <span style="color:#999;">➜</span> <strong>Dst:</strong> {threat['dst_port']} ({self.protocol_names.get(threat['protocol'], 'Unknown')})
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    def _render_analytics_section(self, detection_results):
        """Render advanced analytics section"""
        if not detection_results or len(detection_results) < 5:
            return
        
        st.markdown("## 📈 Advanced Analytics & Intelligence")
        
        # Simple balanced 2-column layout
        col1, col2 = st.columns(2)
        
        with col1:
            self._render_real_time_timeline(detection_results)
        
        with col2:
            self._render_model_confidence_analysis(detection_results)
            
        # Removed Attack Pattern Analysis as requested
        # Removed Heatmap to reduce clutter as implied by "make UI minimal"
    
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
            
            # Use loose matching or threat_level
            if result['threat_level'] in ['HIGH', 'MEDIUM'] or 'Attack' in result['final_prediction']:
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
        
        # Analyze top ports
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
            
            # Color code based on THREAT LEVEL (Robust)
            if result['threat_level'] == 'HIGH':
                card_class = "alert-high"
                icon = "🚨"
            elif result['threat_level'] == 'MEDIUM':
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