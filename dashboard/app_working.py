import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
import os
import sys
from datetime import datetime, timedelta
import time
import subprocess
import signal

sys.path.insert(0, os.path.abspath('..'))

# Page config
st.set_page_config(
    page_title="🛡️ NetGuardAI Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# CSS with alert styles
st.markdown("""
<style>
    .threat-box {
        padding: 20px;
        background: linear-gradient(135deg, #ff0000 0%, #cc0000 100%);
        color: white;
        border-radius: 15px;
        font-weight: bold;
        font-size: 28px;
        text-align: center;
        animation: pulse 0.8s infinite;
        margin: 20px 0;
        box-shadow: 0 8px 25px rgba(255, 0, 0, 0.5);
        border: 4px solid #ff0000;
    }
    
    .normal-box {
        padding: 15px;
        background: linear-gradient(135deg, #00cc00 0%, #009900 100%);
        color: white;
        border-radius: 10px;
        font-weight: bold;
        font-size: 20px;
        text-align: center;
        margin: 15px 0;
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.05); opacity: 0.7; }
    }
</style>
""", unsafe_allow_html=True)

# Paths
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKETS_LOG = os.path.join(base_dir, 'data', 'packets_log.csv')
THREATS_LOG = os.path.join(base_dir, 'data', 'threat_logs.json')
ML_PREDICTIONS = os.path.join(base_dir, 'data', 'ml_predictions.json')
ML_STATS = os.path.join(base_dir, 'data', 'ml_stats.json')

# Session state
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False
if 'last_threat' not in st.session_state:
    st.session_state.last_threat = None

def load_packets():
    """Load packet data"""
    if os.path.exists(PACKETS_LOG):
        try:
            df = pd.read_csv(PACKETS_LOG)
            if 'Timestamp' in df.columns:
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            return df
        except:
            pass
    return pd.DataFrame()

def load_ml_predictions():
    """Load ML predictions"""
    if os.path.exists(ML_PREDICTIONS):
        try:
            with open(ML_PREDICTIONS, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else [data]
        except:
            pass
    return []

def load_ml_stats():
    """Load ML stats"""
    if os.path.exists(ML_STATS):
        try:
            with open(ML_STATS, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def check_analyzer():
    """Check if analyzer is running"""
    try:
        # Windows-compatible process check
        result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq python.exe', '/FO', 'CSV'], 
                              capture_output=True, text=True)
        return 'realtime_analyzer.py' in result.stdout
    except:
        return False

def start_analyzer():
    """Start real-time analyzer - Windows compatible"""
    try:
        # Use system Python instead of virtual environment path
        analyzer_script = os.path.join(base_dir, 'realtime_analyzer.py')
        
        # Start analyzer with system Python
        cmd = ['python', analyzer_script]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                        start_new_session=True, cwd=base_dir)
        
        return True, "Real-time analyzer started!"
    except Exception as e:
        return False, str(e)

def stop_analyzer():
    """Stop analyzer - Windows compatible"""
    try:
        # Windows-compatible process kill
        subprocess.run(['taskkill', '/F', '/IM', 'python.exe', '/FI', 'WINDOWTITLE eq *realtime_analyzer*'], 
                      capture_output=True)
        time.sleep(0.3)
        return True
    except:
        return False

def generate_sample():
    """Generate sample data"""
    try:
        # Use system Python
        cmd = f'python -c "from utils.data_preprocess import generate_sample_data, generate_sample_threats; generate_sample_data(100); generate_sample_threats(20)"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=base_dir)
        return result.returncode == 0
    except:
        return False

# ======HEADER======= 
st.title("🛡️ NetGuardAI - Live Network Security Monitor")
st.markdown("Real-time AI threat detection with instant alerts")

# ======SIDEBAR======= 
with st.sidebar:
    st.header("🎛️ Controls")
    
    # Auto-refresh
    st.session_state.auto_refresh = st.toggle("🔄 Auto-Refresh (2s)", st.session_state.auto_refresh)
    
    st.markdown("---")
    
    # Analyzer
    st.subheader("📡 Analyzer")
    analyzer_on = check_analyzer()
    
    if analyzer_on:
        st.success("✅ Running")
        if st.button("⏹️ Stop", use_container_width=True):
            if stop_analyzer():
                st.success("Stopped!")
                time.sleep(0.3)
                st.rerun()
            else:
                st.error("Failed to stop")
    else:
        st.warning("⚠️ Stopped")
        if st.button("▶️ Start", use_container_width=True):
            success, msg = start_analyzer()
            if success:
                st.success(msg)
                time.sleep(0.5)
                st.rerun()
            else:
                st.error(msg)
    
    st.markdown("---")
    
    # Sample data
    st.subheader("📊 Sample Data")
    if st.button("🎲 Generate", use_container_width=True):
        with st.spinner("Generating..."):
            if generate_sample():
                st.success("✅ Generated!")
                time.sleep(0.3)
                st.rerun()
            else:
                st.error("Failed")

# ========== LOAD DATA ==========
packets_df = load_packets()
predictions = load_ml_predictions()
stats = load_ml_stats()

# ========== THREAT ALERTS ==========
st.markdown("---")

if predictions:
    latest = predictions[-1]
    is_threat = latest.get('is_threat', False)
    
    if is_threat:
        threat_type = latest.get('threat_type', 'Unknown').upper()
        confidence = latest.get('confidence', 0) * 100
        timestamp = latest.get('timestamp', '')
        
        # Show alert
        st.markdown(f"""
        <div class="threat-box">
            🚨 THREAT ALERT 🚨<br>
            {threat_type}<br>
            Confidence: {confidence:.1f}%<br>
            {timestamp}
        </div>
        """, unsafe_allow_html=True)
        
        # Toast
        if st.session_state.last_threat != threat_type:
            st.toast(f"🚨 {threat_type} DETECTED!", icon="🚨")
            st.session_state.last_threat = threat_type
    else:
        confidence = latest.get('confidence', 0) * 100
        st.markdown(f"""
        <div class="normal-box">
            ✅ System Normal (Confidence: {confidence:.1f}%)
        </div>
        """, unsafe_allow_html=True)
        st.session_state.last_threat = None
else:
    st.info("🔄 Waiting for data... Generate sample data or start analyzer")

st.markdown("---")

# ========== TABS ==========
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "📡 Live Packets", "🎯 ML Analysis", "🚨 Threat Intel", "📈 Advanced Stats"])

# ========== TAB 1: OVERVIEW ==========
with tab1:
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total = stats.get('total_packets', len(packets_df))
        st.metric("Packets", f"{total:,}")
    
    with col2:
        preds = len(predictions)
        st.metric("Predictions", f"{preds:,}")
    
    with col3:
        threats = sum(1 for p in predictions if p.get('is_threat', False))
        st.metric("Threats", threats)
    
    with col4:
        if predictions:
            ts = predictions[-1].get('timestamp', 'N/A')
            if 'T' in ts:
                ts = ts.split('T')[1][:8]
            st.metric("Last Update", ts)
        else:
            st.metric("Last Update", "N/A")
    
    st.markdown("---")
    
    # Timeline chart
    if predictions and len(predictions) > 1:
        st.subheader("🔴 Live Activity")
        
        times = []
        confs = []
        colors = []
        
        for p in predictions[-50:]:
            ts = p.get('timestamp', '')
            if 'T' in ts:
                ts = ts.split('T')[1][:8]
            times.append(ts)
            confs.append(p.get('confidence', 0) * 100)
            colors.append('#ff0000' if p.get('is_threat', False) else '#00cc00')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=times,
            y=confs,
            mode='lines+markers',
            line=dict(color='#0066cc', width=2),
            marker=dict(size=8, color=colors, line=dict(width=1, color='white'))
        ))
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Confidence (%)",
            height=350,
            showlegend=False,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        
        st.plotly_chart(fig, config={"displayModeBar": False})

# ========== TAB 2: LIVE PACKETS ==========
with tab2:
    st.header("📡 Live Network Packets")
    
    time_filter = st.selectbox("Time Range", 
        ["Last 1 minute", "Last 5 minutes", "Last 15 minutes", "Last 1 hour", "All time"],
        index=1)
    
    if not packets_df.empty:
        now = datetime.now()
        
        if time_filter == "Last 1 minute":
            df = packets_df[packets_df['Timestamp'] > now - timedelta(minutes=1)]
        elif time_filter == "Last 5 minutes":
            df = packets_df[packets_df['Timestamp'] > now - timedelta(minutes=5)]
        elif time_filter == "Last 15 minutes":
            df = packets_df[packets_df['Timestamp'] > now - timedelta(minutes=15)]
        elif time_filter == "Last 1 hour":
            df = packets_df[packets_df['Timestamp'] > now - timedelta(hours=1)]
        else:
            df = packets_df
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Packets", len(df))
        with col2:
            src = 'Src_IP' if 'Src_IP' in df.columns else 'Source IP'
            st.metric("Unique IPs", df[src].nunique() if src in df.columns else 0)
        with col3:
            st.metric("Protocols", df['Protocol'].nunique())
        with col4:
            size = 'Size' if 'Size' in df.columns else 'Packet Size'
            avg = df[size].mean() if size in df.columns else 0
            st.metric("Avg Size", f"{avg:.0f}B")
        
        st.markdown("---")
        st.subheader(f"🔴 Live: {len(df)} packets")
        
        display = df.sort_values('Timestamp', ascending=False).head(100)
        st.dataframe(display, height=400)
    else:
        st.warning("No packets. Generate sample data or start analyzer.")

# ========== TAB 3: ML ANALYSIS ==========
with tab3:
    st.header("🎯 ML Prediction Analysis")
    
    if predictions:
        # Summary metrics
        total_preds = len(predictions)
        threat_preds = sum(1 for p in predictions if p.get('is_threat', False))
        normal_preds = total_preds - threat_preds
        threat_rate = (threat_preds / total_preds * 100) if total_preds > 0 else 0
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Predictions", total_preds)
        with col2:
            st.metric("✅ Normal", normal_preds, delta=f"{(normal_preds/total_preds*100):.1f}%")
        with col3:
            st.metric("🚨 Threats", threat_preds, delta=f"{threat_rate:.1f}%", delta_color="inverse")
        with col4:
            avg_conf = sum(p.get('confidence', 0) for p in predictions) / len(predictions) * 100
            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
        
        st.markdown("---")
        
        # Prediction timeline
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Prediction Distribution")
            
            fig = go.Figure(data=[go.Pie(
                labels=['Normal', 'Threat'],
                values=[normal_preds, threat_preds],
                marker=dict(colors=['#00cc00', '#ff0000']),
                hole=0.5
            )])
            
            fig.update_layout(
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                annotations=[dict(text=f'{threat_rate:.1f}%<br>Threat Rate', x=0.5, y=0.5, font_size=16, showarrow=False)]
            )
            
            st.plotly_chart(fig, config={"displayModeBar": False})
        
        with col2:
            st.subheader("📈 Confidence Distribution")
            
            confidences = [p.get('confidence', 0) * 100 for p in predictions]
            
            fig = go.Figure(data=[go.Histogram(
                x=confidences,
                nbinsx=20,
                marker=dict(color='#0066cc')
            )])
            
            fig.update_layout(
                xaxis_title="Confidence (%)",
                yaxis_title="Count",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                showlegend=False
            )
            
            st.plotly_chart(fig, config={"displayModeBar": False})
        
        st.markdown("---")
        
        # Recent predictions
        st.subheader("📋 Recent Predictions")
        
        for pred in reversed(predictions[-10:]):
            is_threat = pred.get('is_threat', False)
            threat_type = pred.get('threat_type', 'normal')
            conf = pred.get('confidence', 0) * 100
            ts = pred.get('timestamp', '')
            
            if 'T' in ts:
                ts = ts.split('T')[1][:8]
            
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                if is_threat:
                    st.error(f"🚨 **THREAT**: {threat_type.replace('_', ' ').upper()}")
                else:
                    st.success(f"✅ **NORMAL TRAFFIC**")
            
            with col2:
                st.write(f"**Confidence**: {conf:.1f}%")
                st.progress(conf / 100)
            
            with col3:
                st.caption(f"⏰ {ts}")
            
            st.markdown("---")
    else:
        st.info("No predictions yet. Start analyzer to see ML analysis.")

# ========== TAB 4: THREAT INTELLIGENCE ==========
with tab4:
    st.header("🚨 Threat Intelligence Dashboard")
    
    if predictions:
        threats = [p for p in predictions if p.get('is_threat', False)]
        
        if threats:
            # Threat metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("🚨 Total Threats", len(threats))
            
            with col2:
                # Threat types
                threat_types = {}
                for t in threats:
                    tt = t.get('threat_type', 'unknown')
                    threat_types[tt] = threat_types.get(tt, 0) + 1
                most_common = max(threat_types, key=lambda x: threat_types[x]) if threat_types else "N/A"
                st.metric("Most Common", str(most_common).replace('_', ' ').title())
            
            with col3:
                avg_threat_conf = sum(t.get('confidence', 0) for t in threats) / len(threats) * 100
                st.metric("Avg Threat Confidence", f"{avg_threat_conf:.1f}%")
            
            with col4:
                recent_threats = len([t for t in threats[-10:] if t in threats[-5:]])
                st.metric("Recent Threats (last 5)", recent_threats, delta="⚠️" if recent_threats > 2 else "✓")
            
            st.markdown("---")
            
            # Threat visualization
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🎯 Threat Types Distribution")
                
                if threat_types:
                    labels = [k.replace('_', ' ').title() for k in threat_types.keys()]
                    values = list(threat_types.values())
                    
                    fig = go.Figure(data=[go.Bar(
                        x=labels,
                        y=values,
                        marker=dict(color='#ff0000')
                    )])
                    
                    fig.update_layout(
                        xaxis_title="Threat Type",
                        yaxis_title="Count",
                        height=300,
                        margin=dict(l=20, r=20, t=20, b=20)
                    )
                    
                    st.plotly_chart(fig, config={"displayModeBar": False})
            
            with col2:
                st.subheader("⚠️ Threat Severity Timeline")
                
                # Create timeline of threats
                times = []
                confs = []
                for t in threats[-20:]:
                    ts = t.get('timestamp', '')
                    if 'T' in ts:
                        ts = ts.split('T')[1][:8]
                    times.append(ts)
                    confs.append(t.get('confidence', 0) * 100)
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=times,
                    y=confs,
                    mode='lines+markers',
                    marker=dict(size=10, color='#ff0000'),
                    line=dict(color='#ff0000', width=2),
                    fill='tozeroy',
                    fillcolor='rgba(255, 0, 0, 0.2)'
                ))
                
                fig.update_layout(
                    xaxis_title="Time",
                    yaxis_title="Confidence (%)",
                    height=300,
                    margin=dict(l=20, r=20, t=20, b=20),
                    showlegend=False
                )
                
                st.plotly_chart(fig, config={"displayModeBar": False})
            
            st.markdown("---")
            
            # Detailed threat list
            st.subheader("📋 Threat Details")
            
            threat_data = []
            for t in reversed(threats[-15:]):
                ts = t.get('timestamp', '')
                if 'T' in ts:
                    ts = ts.split('T')[1][:8]
                
                threat_data.append({
                    'Time': ts,
                    'Type': t.get('threat_type', 'unknown').replace('_', ' ').title(),
                    'Confidence': f"{t.get('confidence', 0) * 100:.1f}%",
                    'Severity': '🔴 High' if t.get('confidence', 0) > 0.8 else '🟠 Medium'
                })
            
            if threat_data:
                df_threats = pd.DataFrame(threat_data)
                st.dataframe(df_threats, height=300, use_container_width=True)
        else:
            st.success("🎉 No threats detected! System is secure.")
            st.info("All network traffic appears normal. Continue monitoring for any anomalies.")
    else:
        st.info("No threat data available yet. Start analyzer to begin threat monitoring.")

# ========== TAB 5: ADVANCED STATISTICS ==========
with tab5:
    st.header("📈 Advanced Network Statistics")
    
    if not packets_df.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            # Protocol pie
            proto = packets_df['Protocol'].value_counts()
            
            fig = go.Figure(data=[go.Pie(
                labels=proto.index,
                values=proto.values,
                hole=0.4
            )])
            
            fig.update_layout(
                title="Protocols",
                height=350,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            st.plotly_chart(fig, config={"displayModeBar": False})
        
        with col2:
            # Top IPs
            src = 'Src_IP' if 'Src_IP' in packets_df.columns else 'Source IP'
            if src in packets_df.columns:
                top = packets_df[src].value_counts().head(10)
                
                fig = go.Figure(data=[go.Bar(
                    x=top.values,
                    y=top.index,
                    orientation='h',
                    marker=dict(color='#0066cc')
                )])
                
                fig.update_layout(
                    title="Top 10 IPs",
                    xaxis_title="Count",
                    height=350,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                
                st.plotly_chart(fig, config={"displayModeBar": False})
        
        st.markdown("---")
        
        # Additional charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📦 Packet Size Distribution")
            size_col = 'Size' if 'Size' in packets_df.columns else 'Packet Size'
            if size_col in packets_df.columns:
                fig = go.Figure(data=[go.Histogram(
                    x=packets_df[size_col],
                    nbinsx=30,
                    marker=dict(color='#109618')
                )])
                
                fig.update_layout(
                    xaxis_title="Packet Size (bytes)",
                    yaxis_title="Frequency",
                    height=300,
                    margin=dict(l=20, r=20, t=20, b=20),
                    showlegend=False
                )
                
                st.plotly_chart(fig, config={"displayModeBar": False})
        
        with col2:
            st.subheader("🔢 Top Destination Ports")
            dst_port_col = 'Dst_Port' if 'Dst_Port' in packets_df.columns else 'Destination Port'
            if dst_port_col in packets_df.columns:
                top_ports = packets_df[dst_port_col].value_counts().head(10)
                
                fig = go.Figure(data=[go.Bar(
                    x=top_ports.index.astype(str),
                    y=top_ports.values,
                    marker=dict(color='#dc3912')
                )])
                
                fig.update_layout(
                    xaxis_title="Port",
                    yaxis_title="Count",
                    height=300,
                    margin=dict(l=20, r=20, t=20, b=20),
                    showlegend=False
                )
                
                st.plotly_chart(fig, config={"displayModeBar": False})
        
        st.markdown("---")
        
        # Traffic timeline
        if 'Timestamp' in packets_df.columns:
            st.subheader("📈 Network Traffic Over Time")
            
            packets_df['Minute'] = pd.to_datetime(packets_df['Timestamp']).dt.floor('1min')
            traffic = packets_df.groupby('Minute').size().reset_index(name='count')
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=traffic['Minute'],
                y=traffic['count'],
                mode='lines+markers',
                marker=dict(size=6, color='#0066cc'),
                line=dict(color='#0066cc', width=2),
                fill='tozeroy',
                fillcolor='rgba(0, 102, 204, 0.2)'
            ))
            
            fig.update_layout(
                xaxis_title="Time",
                yaxis_title="Packets per Minute",
                height=300,
                margin=dict(l=20, r=20, t=20, b=20),
                showlegend=False
            )
            
            st.plotly_chart(fig, config={"displayModeBar": False})
    else:
        st.info("No data for statistics")

# ========== AUTO REFRESH ==========
if st.session_state.auto_refresh:
    time.sleep(2)
    st.rerun()