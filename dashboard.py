import streamlit as st
import pandas as pd
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

class DDOSDetectionDashboard:
    def __init__(self):
        self.threat_colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107', 
            'HIGH': '#dc3545',
            'UNKNOWN': '#6c757d'
        }
    
    def render(self, detection_results, system_running):
        """Render the main dashboard"""
        
        # Main title
        st.title("🛡️ Real-Time DDoS Detection System")
        
        # System status banner
        if system_running:
            st.success("🟢 **SYSTEM ACTIVE** - Real-time monitoring in progress")
        else:
            st.error("🔴 **SYSTEM STOPPED** - No active monitoring")
        
        # Metrics overview
        self._render_metrics(detection_results)
        
        # Real-time alerts
        self._render_alerts(detection_results)
        
        # Detection results table
        self._render_detection_table(detection_results)
        
        # Visualizations
        self._render_visualizations(detection_results)
    
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
        recent_threats = [r for r in recent_flows if r['final_prediction'] == 'Attack']
        
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
    
    def _render_detection_table(self, detection_results):
        """Render detection results table"""
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
        
        st.dataframe(styled_df, use_container_width=True)
    
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
