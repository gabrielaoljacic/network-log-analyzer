import streamlit as st
import pandas as pd
import plotly.express as px
from src.log_generator import generate_simple_logs
from src.log_parser import LogParser
from src.analyzer import LogAnalyzer

def init_session_state():
    """Initialize all session state variables"""
    defaults = {
        'df': None,
        'analyzer': None,
        'data_loaded': False
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

def load_sample_data():
    """Load or generate sample data"""
    if not st.session_state.data_loaded:
        with st.spinner("Loading sample data..."):
            logs = generate_simple_logs(500)
            parser = LogParser()
            df = parser.parse_logs(logs)
            st.session_state.df = parser.clean_logs(df)
            st.session_state.analyzer = LogAnalyzer(st.session_state.df)
            st.session_state.data_loaded = True

def main():
    st.set_page_config(layout="wide", page_title="AI Log Analyzer")
    init_session_state()
    
    # Sidebar Controls
    with st.sidebar:
        st.header("Controls")
        if st.button("Load Sample Data"):
            load_sample_data()
        
        if st.session_state.data_loaded:
            view_mode = st.radio(
                "View Mode",
                ["Overview", "Anomalies", "Clusters"]
            )
    
    # Main Display
    st.title("🛡️ AI-Powered Network Log Analysis")
    
    if not st.session_state.data_loaded:
        st.info("Click 'Load Sample Data' to begin")
        return
    
    if view_mode == "Overview":
        show_overview()
    elif view_mode == "Anomalies":
        show_anomalies()
    else:
        show_clusters()

def show_overview():
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Event Timeline")
        time_col = next((col for col in ['timestamp', 'time'] if col in st.session_state.df.columns), None)
        if time_col:
            fig = px.histogram(
                st.session_state.df,
                x=time_col,
                color='level' if 'level' in st.session_state.df.columns else 'action',
                nbins=24
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Protocol Distribution" if 'protocol' in st.session_state.df.columns else "Action Types")
        if 'protocol' in st.session_state.df.columns:
            fig = px.pie(st.session_state.df, names='protocol')
        else:
            fig = px.bar(st.session_state.df['action'].value_counts())
        st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Sample Logs")
    st.dataframe(st.session_state.df.head(10))

def show_anomalies():
    try:
        analyzer = st.session_state.analyzer
        
        # Get anomalies (using hybrid detection)
        anomalies = analyzer.detect_anomalies(method='hybrid')
        
        st.subheader("Detected Anomalies")
        if anomalies:
            # Convert to DataFrame for display
            anomalies_df = pd.DataFrame(anomalies)
            
            # Display top anomalies
            st.dataframe(anomalies_df.head(10))
            
            # Detailed inspection
            selected = st.selectbox(
                "Inspect Anomaly", 
                anomalies_df.index,
                format_func=lambda x: f"{anomalies_df.loc[x, 'type']} ({anomalies_df.loc[x].get('source_ip', 'N/A')})"
            )
            
            # Safely get sample message
            sample_msg = ""
            if 'sample_messages' in anomalies_df.columns:
                msg_data = anomalies_df.loc[selected, 'sample_messages']
                if isinstance(msg_data, list) and len(msg_data) > 0:
                    sample_msg = msg_data[0]
                elif isinstance(msg_data, str):
                    sample_msg = msg_data
            
            # Display analysis
            st.json({
                'details': anomalies_df.loc[selected].to_dict(),
                'analysis': analyzer.analyze_message(sample_msg or "Anomaly detected")
            })
        else:
            st.success("No anomalies detected!")
            
    except Exception as e:
        st.error(f"Anomaly detection failed: {str(e)}")

def show_clusters():
    try:
        analyzer = st.session_state.analyzer
        clusters = analyzer.cluster_logs()
        
        st.subheader("Log Clusters")
        if not clusters.empty:
            st.dataframe(clusters)
            
            selected_cluster = st.selectbox(
                "Explore Cluster",
                clusters['cluster'].unique()
            )
            cluster_logs = st.session_state.df[
                st.session_state.df['cluster'] == selected_cluster
            ]
            st.dataframe(cluster_logs[['message', 'timestamp']])
        else:
            st.warning("No clusters found")
            
    except Exception as e:
        st.error(f"Clustering failed: {str(e)}")

if __name__ == "__main__":
    main()