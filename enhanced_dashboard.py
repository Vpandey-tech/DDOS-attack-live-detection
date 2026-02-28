import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta
import plotly.graph_objects as go
from plotly.subplots import make_subplots

class EnhancedDDOSDetectionDashboard:
    def __init__(self):
        self.protocol_names = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP' }
        self.setup_page_style()

    def setup_page_style(self):
        """Minimalist, 'Stitch'-like designer aesthetic: Light mode, elegant typography."""
        st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap');
        
        /* Global typography */
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif !important;
            color: #1e293b;
        }

        /* Top Header Container */
        .header-box {
            background: #ffffff;  
            border: 1px solid #e2e8f0;
            padding: 1.25rem 1.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
        }
        .header-title { font-size: 1.25rem; font-weight: 600; color: #0f172a; margin: 0; }
        .header-subtitle { font-size: 0.8rem; color: #64748b; margin: 0; font-weight: 400; margin-top: 0.2rem;}
        
        .badge-active { padding: 0.35rem 0.8rem; background: #ecfdf5; border: 1px solid #a7f3d0; color: #059669; border-radius: 6px; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.3px;}
        .badge-paused { padding: 0.35rem 0.8rem; background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; border-radius: 6px; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.3px;}

        /* KPI Cards */
        .kpi { background: #ffffff; border: 1px solid #e2e8f0; padding: 1.25rem; border-radius: 10px; height: 100%; display: flex; flex-direction: column; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .kpi-title { font-size: 0.75rem; color: #64748b; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
        .kpi-value { font-size: 1.75rem; font-weight: 600; color: #0f172a; margin-top: 0.5rem; letter-spacing: -0.02em; }
        .kpi-sub { font-size: 0.75rem; color: #94a3b8; margin-top: 0.5rem; }

        /* Section Titles */
        .sec-title { font-size: 0.8rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.05em; margin: 2rem 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid #e2e8f0; }

        /* General UI cleanup */
        header, footer, #MainMenu { visibility: hidden; display: none; }
        .block-container { max-width: 1400px; padding-top: 2rem; padding-bottom: 2rem; }
        
        </style>
        """, unsafe_allow_html=True)

    def render(self, detection_results, system_running, simulation_stats=None):
        """Render the minimalist UI"""
        
        # Header Box
        status_html = '<span class="badge-active">● MONITORING ACTIVE</span>' if system_running else '<span class="badge-paused">● MONITORING PAUSED</span>'
        if simulation_stats and simulation_stats.get('running'):
            mode = simulation_stats.get('attack_type', 'None')
            status_html += f'&nbsp;<span class="badge-active" style="color:#0284c7; border-color:#bae6fd; background:#e0f2fe;">● SIMULATOR ({mode})</span>'

        st.markdown(f"""
        <div class="header-box">
            <div>
                <p class="header-title">DDoS Detection Platform</p>
                <p class="header-subtitle">Ensemble Intelligence — LUCID · Autoencoder · XGBoost · Random Forest</p>
            </div>
            <div>
                {status_html}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Calculate KPIs
        total_flows = len(detection_results)
        threats_detected = sum(1 for r in detection_results if 'Attack' in r['final_prediction'])
        recent = detection_results[-100:] if len(detection_results) > 100 else detection_results
        recent_threats = sum(1 for r in recent if 'Attack' in r['final_prediction'])
        attack_rate = (recent_threats / len(recent) * 100) if recent else 0

        # Latency (mock or calculated)
        latency = f"{np.mean([r.get('inference_time_ms', 14) for r in recent[-20:]]):.0f}ms" if recent else "—"

        # Output KPIs
        k1, k2, k3, k4 = st.columns(4)
        kpis = [
            (k1, "Total Packets Analyzed", f"{total_flows:,}", "Cumulative flows processed"),
            (k2, "Threats Detected", f"{threats_detected:,}", "Total intercepted attacks"),
            (k3, "Current Attack Rate", f"{attack_rate:.1f}%", "Based on last 100 flows"),
            (k4, "Inference Latency", latency, "Average model response time")
        ]
        
        for col, title, val, sub in kpis:
            with col:
                st.markdown(f"""
                <div class="kpi">
                    <div class="kpi-title">{title}</div>
                    <div class="kpi-value">{val}</div>
                    <div class="kpi-sub">{sub}</div>
                </div>
                """, unsafe_allow_html=True)

        # Two-column layout for main content
        col_main, col_side = st.columns([12, 5], gap="large")

        with col_main:
            st.markdown('<div class="sec-title">Real-Time Traffic Feed</div>', unsafe_allow_html=True)
            self._render_dataframe_feed(detection_results)

            st.markdown('<div class="sec-title">Traffic Analysis Timeline</div>', unsafe_allow_html=True)
            self._render_real_time_timeline(detection_results)

        with col_side:
            st.markdown('<div class="sec-title">Active Threat Alerts</div>', unsafe_allow_html=True)
            self._render_threat_alerts(detection_results)

            st.markdown('<div class="sec-title">Protocol Distribution</div>', unsafe_allow_html=True)
            self._render_attack_pattern_analysis(detection_results)

    def _render_dataframe_feed(self, detection_results):
        """Uses native st.dataframe to provide a smooth, persistent, scrollable table rather than jumping HTML divs."""
        if not detection_results:
            st.markdown("<p style='color:#64748b; font-size:0.85rem;'>Waiting for network traffic...</p>", unsafe_allow_html=True)
            return

        # Prepare a structured pandas dataframe
        data = []
        # Take the most recent 200 items for the table to keep it very fast and responsive
        for r in list(reversed(detection_results))[:200]:
            ts = datetime.fromtimestamp(r['timestamp']).strftime('%H:%M:%S.%f')[:-3]
            proto = self.protocol_names.get(r['protocol'], f"P-{r['protocol']}")
            conf = f"{r['lucid_confidence'] * 100:.1f}%"
            anomaly = 'Yes' if r['autoencoder_anomaly'] else 'No'
            
            # Formulate clear strings
            source = f"{r['src_ip']}:{r['src_port']}"
            dest = f"{r['dst_ip']}:{r['dst_port']}"
            
            data.append({
                "Time": ts,
                "Source": source,
                "Destination": dest,
                "Protocol": proto,
                "Prediction": r['final_prediction'],
                "Confidence": conf,
                "Level": r['threat_level']
            })

        df = pd.DataFrame(data)
        
        # Display as an interactive dataframe. This locks height to 400px and scrolls natively.
        st.dataframe(
            df, 
            hide_index=True, 
            use_container_width=True, 
            height=300,
        )

    def _render_threat_alerts(self, detection_results):
        """Minimal threat list without breaking layout"""
        recent_threats = [
            r for r in reversed(detection_results[-100:])
            if r['threat_level'] in ['HIGH', 'MEDIUM']
        ][:5]

        if not recent_threats:
            st.markdown("""
            <div style="padding: 1rem; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 0.8rem; color: #059669;  background: #f8fafc;">
                No active threats detected. System is secure.
            </div>
            """, unsafe_allow_html=True)
            return

        for t in recent_threats:
            t_time = datetime.fromtimestamp(t['timestamp']).strftime('%H:%M:%S')
            is_high = t['threat_level'] == 'HIGH'
            border_col = '#ef4444' if is_high else '#f59e0b'
            lbl = 'CRITICAL' if is_high else 'WARNING'
            
            st.markdown(f"""
            <div style="padding: 0.8rem; border: 1px solid #e2e8f0; border-left: 3px solid {border_col}; border-radius: 6px; margin-bottom: 0.5rem; background: #ffffff; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size: 0.75rem; font-weight: 600; color:{border_col};">{lbl}</span>
                    <span style="font-size: 0.7rem; color: #64748b;">{t_time}</span>
                </div>
                <div style="font-size: 0.75rem; color: #475569; margin-top: 0.3rem; font-family: monospace;">
                    {t['src_ip']} → {t['dst_port']}
                </div>
            </div>
            """, unsafe_allow_html=True)

    def _render_real_time_timeline(self, detection_results):
        """Plotly chart for traffic analysis"""
        if len(detection_results) < 2:
            st.markdown("<p style='color:#64748b; font-size:0.85rem;'>Insufficient data for timeline...</p>", unsafe_allow_html=True)
            return

        timeline_data = {}
        # Use 10-second intervals for real-time feel
        for result in detection_results[-300:]:
            key = int(result['timestamp'] // 10) * 10
            if key not in timeline_data:
                timeline_data[key] = {'total': 0, 'attacks': 0}
            timeline_data[key]['total'] += 1
            if result['threat_level'] in ['HIGH', 'MEDIUM'] or 'Attack' in result['final_prediction']:
                timeline_data[key]['attacks'] += 1
        
        times = [datetime.fromtimestamp(ts) for ts in sorted(timeline_data.keys())]
        totals = [timeline_data[ts]['total'] for ts in sorted(timeline_data.keys())]
        attacks = [timeline_data[ts]['attacks'] for ts in sorted(timeline_data.keys())]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=totals, name='Total Traffic', line=dict(color='#3b82f6', width=2), fill='tozeroy', fillcolor='rgba(59, 130, 246, 0.1)'))
        fig.add_trace(go.Scatter(x=times, y=attacks, name='Threats', line=dict(color='#ef4444', width=2), fill='tozeroy', fillcolor='rgba(239, 68, 68, 0.1)'))
        
        fig.update_layout(
            height=280,
            margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#475569', family="Inter"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, xanchor="left", font=dict(size=11)),
            xaxis=dict(gridcolor='#e2e8f0', zeroline=False, fixedrange=True),
            yaxis=dict(gridcolor='#e2e8f0', zeroline=False, title='Flows/10s', fixedrange=True)
        )
        # Using config to disable mode bar for cleaner look
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    def _render_attack_pattern_analysis(self, detection_results):
        """Pie chart of attacked protocols"""
        attacks = [r for r in detection_results if 'Attack' in r['final_prediction']]
        if not attacks:
            st.markdown("<p style='color:#64748b; font-size:0.85rem; text-align:center; padding: 2rem 0;'>No attacks analyzed</p>", unsafe_allow_html=True)
            return

        counts = {}
        for a in attacks[-500:]:
            p = self.protocol_names.get(a['protocol'], 'Other')
            counts[p] = counts.get(p, 0) + 1
        
        fig = go.Figure(data=[go.Pie(
            labels=list(counts.keys()),
            values=list(counts.values()),
            hole=0.6,
            marker_colors=['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
            textinfo='percent'
        )])
        fig.update_layout(
            height=240,
            margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            font=dict(color='#475569', family="Inter", size=11),
            legend=dict(yanchor="middle", y=0.5, xanchor="left", x=1)
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})