import streamlit as st
import pandas as pd
from db_service import SentinelDBManager
import viz_engine as ve

# Configure Streamlit page settings
st.set_page_config(
    page_title="SentinelDB | Global Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply custom CSS for 'Dark Mode' Cybersecurity Theme
def apply_custom_css():
    st.markdown("""
        <style>
            /* Base dark theme overrides */
            .stApp {
                background-color: #0b1117;
                color: #c9d1d9;
            }
            .css-1d391kg, .st-emotion-cache-16txtl3 {  /* Sidebar */
                background-color: #161b22;
            }
            /* Metric Cards Styling */
            div[data-testid="metric-container"] {
                background-color: #1c2128;
                border: 1px solid #30363d;
                padding: 5% 5% 5% 10%;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.3);
                color: #58a6ff;
            }
            div[data-testid="metric-container"] > label {
                font-size: 1.2rem !important;
                color: #8b949e !important;
            }
            div[data-testid="stMetricValue"] {
                font-size: 2.5rem !important;
                font-weight: 800 !important;
                color: #ff7b72 !important;
            }
            /* Button styling for lockdown */
            .stButton>button {
                background-color: #da3633;
                color: white;
                font-weight: bold;
                border: 1px solid #b62324;
                border-radius: 6px;
                width: 100%;
                padding: 0.5rem 1rem;
                transition: all 0.3s;
            }
            .stButton>button:hover {
                background-color: #b62324;
                border-color: #b62324;
                color: white;
                box-shadow: 0 0 10px rgba(218, 54, 51, 0.5);
            }
            /* Inputs and DataFrames */
            .stTextInput>div>div>input {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
            }
            h1, h2, h3 {
                color: #58a6ff !important;
            }
        </style>
    """, unsafe_allow_html=True)

apply_custom_css()

# Initialize DB connection in Streamlit session state
if 'db' not in st.session_state:
    st.session_state.db = SentinelDBManager() # Uses the default root password
    try:
        st.session_state.db.connect()
    except Exception as e:
        # Fails silently for the UI if no DB is preset, but will show warnings later
        pass

# Sidebar Navigation
st.sidebar.markdown("## 🛡️ Sentinel DB")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation Menu", ["Overview", "Breach Simulator", "System Audit"])

if page == "Overview":
    st.title("🌐 Command Center Overview")
    st.markdown("Real-time threat and risk telemetry for the SentinelDB framework.")
    
    # Show KPIs
    if st.session_state.db.conn and st.session_state.db.conn.is_connected():
        analytics = st.session_state.db.fetch_risk_analytics()
        if analytics:
            # Dummy logic to calculate sys_health (100 - penalty per compromised user)
            sys_health = max(0, 100 - (analytics['compromised_users_count'] * 5))
            
            avg_risk = 0
            if analytics['top_5_highest_risk_users']:
                scores = [u['aggregate_risk_score'] for u in analytics['top_5_highest_risk_users']]
                avg_risk = sum(scores) / len(scores)

            kpi_fig = ve.generate_kpi_gauges(sys_health, avg_risk)
            st.plotly_chart(kpi_fig, use_container_width=True)
            
            st.subheader("High-Risk Users (Top 5 Active Threats)")
            df_risk = pd.DataFrame(analytics['top_5_highest_risk_users'])
            if not df_risk.empty:
                st.dataframe(df_risk, use_container_width=True)
            else:
                st.info("No risky users found.")
        else:
            st.warning("No telemetry available from analytics Engine.")
    else:
        st.error("🔒 Database is not connected. Please ensure SentinelDB MySQL instance is running.")


elif page == "Breach Simulator":
    st.title("🚨 Breach Simulator & Lockdown")
    st.markdown("Simulate the impact of a compromised internal identity and initiate containment protocols.")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Identity Selector")
        target_id = st.text_input("Enter Target User ID to Simulate", value="1")
        
        if st.button("Run Impact Simulation"):
            if target_id.isdigit():
                st.session_state.sim_user_id = int(target_id)
                st.session_state.sim_run = True
            else:
                st.error("Please enter a valid numeric User ID.")
    
    # Display the results if simulation ran
    if st.session_state.get('sim_run') and 'sim_user_id' in st.session_state:
        if st.session_state.db.conn and st.session_state.db.conn.is_connected():
            df_impact = st.session_state.db.run_impact_simulation(st.session_state.sim_user_id)
            
            if df_impact is not None and not df_impact.empty:
                username = df_impact['username'].iloc[0]
                risk_score = df_impact['aggregate_risk_score'].iloc[0]
                highest_sens = df_impact['highest_sensitivity_in_table'].max()
                
                # Determine Exposure Level
                if highest_sens == 5:
                    exposure_level = "CRITICAL (P1)"
                elif highest_sens >= 3:
                    exposure_level = "RESTRICTED (P2)"
                else:
                    exposure_level = "INTERNAL (P3)"
                    
                st.markdown("---")
                st.subheader(f"Simulation Results: [Identity: {username}]")
                
                # Big, Bold Cards for Risk Metrics
                mcol1, mcol2, mcol3 = st.columns(3)
                with mcol1:
                    st.metric(label="Aggregate Risk Score", value=f"{risk_score}")
                with mcol2:
                    st.metric(label="Max Exposure Level", value=f"Level {highest_sens}")
                with mcol3:
                    st.metric(label="Threat Classification", value=exposure_level)
                    
                st.markdown("<br>", unsafe_allow_html=True)
                
                # Show Visualizations
                st.subheader("Data Exposure Pathways")
                st.dataframe(df_impact[['database_name', 'table_name', 'sensitive_columns_accessed', 'highest_sensitivity_in_table']], use_container_width=True)
                
                # Generate Impact Chart Data by classifying the tables accessed
                sens_counts = {'Public': 0, 'Internal': 0, 'Restricted': 0, 'Critical': 0}
                for sens in df_impact['highest_sensitivity_in_table']:
                    if sens <= 2: sens_counts['Internal'] += 1
                    elif sens <= 3: sens_counts['Restricted'] += 1
                    else: sens_counts['Critical'] += 1
                
                fig_impact = ve.generate_impact_chart(sens_counts)
                st.plotly_chart(fig_impact, use_container_width=True)
                
                st.markdown("---")
                st.subheader("Containment Action")
                st.warning("⚠️ Executing a lockdown will instantly revoke administrative database connections and all SQL permissions for this user.")
                
                if st.button("🔴 TRIGGER IMMEDIATE LOCKDOWN", key="lockdown_btn"):
                    success = st.session_state.db.trigger_lockdown(
                        st.session_state.sim_user_id, 
                        f"Automated lockdown via Breach Simulator. Entity: {username}"
                    )
                    if success:
                        st.success(f"✅ SUCCESS: Identity {username} (ID: {st.session_state.sim_user_id}) has been isolated and status REVOKED.")
                        st.balloons()
                    else:
                        st.error("Lockdown sequence failed. Check database connection or permissions.")
            else:
                st.warning(f"No impact data found for User ID {st.session_state.sim_user_id}. The user might not exist or has no active data permissions.")
        else:
            st.error("Database connection unavailable. Cannot run simulation.")

elif page == "System Audit":
    st.title("📜 Security Audit Logs")
    st.markdown("Review system-level lockdown events and compliance verifications.")
    
    if st.session_state.db.conn and st.session_state.db.conn.is_connected():
        try:
            cursor = st.session_state.db.conn.cursor(dictionary=True)
            cursor.execute("SELECT log_id, user_id, action_taken, action_timestamp, details FROM Security_Audit_Log ORDER BY action_timestamp DESC")
            logs = cursor.fetchall()
            df_logs = pd.DataFrame(logs)
            if not df_logs.empty:
                st.dataframe(df_logs, use_container_width=True)
            else:
                st.info("No security audit logs recorded yet. System is clear.")
        except Exception as e:
            st.error(f"Failed to fetch audit logs: {e}")
        finally:
            if 'cursor' in locals() and cursor is not None:
                cursor.close()
    else:
        st.error("Database connection unavailable.")
