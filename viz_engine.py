import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go

def generate_risk_heatmap(department_risk_df):
    """
    Generates a heatmap using Matplotlib/Seaborn showing which Departments 
    have the highest concentration of 'Critical' (Level 5) data assets.
    
    Args:
        department_risk_df (pd.DataFrame): 2D DataFrame where index=Department, 
                                           columns=System_Name, 
                                           values=Critical_Count.
    
    Returns:
        matplotlib.figure.Figure: The generated matplotlib figure.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    
    if department_risk_df.empty:
        ax.text(0.5, 0.5, "No Heatmap Data Available", ha='center', va='center', fontsize=14)
        ax.axis('off')
        return fig

    # Plot the heatmap using seaborn for stylized YlOrRd color map
    sns.heatmap(department_risk_df, annot=True, cmap="YlOrRd", linewidths=.5, ax=ax, fmt="g")
    
    ax.set_title("Concentration of Critical (Level 5) Assets by Department", fontsize=15, pad=15, fontweight='bold')
    ax.set_ylabel("Department", fontsize=12, fontweight='bold')
    ax.set_xlabel("Data System / Asset Group", fontsize=12, fontweight='bold')
    
    # Improve layout to prevent cutoff
    plt.tight_layout()
    return fig


def generate_impact_chart(sensitivity_counts):
    """
    Generates a multi-colored Bar Chart using Plotly showing the distribution 
    of sensitivity levels (Public, Internal, Restricted, Critical) for a breached user.
    
    Args:
        sensitivity_counts (pd.Series or dict): Mapping of sensitivity labels to counts.
            Example: {'Public': 40, 'Internal': 25, 'Restricted': 15, 'Critical': 4}
    
    Returns:
        plotly.graph_objects.Figure: The generated Plotly figure.
    """
    # Cast to dict if necessary
    if isinstance(sensitivity_counts, pd.Series):
        counts = sensitivity_counts.to_dict()
    else:
        counts = sensitivity_counts
        
    labels = list(counts.keys())
    values = list(counts.values())
    
    # Define custom colors explicitly for mapping exact Risk Levels
    color_map = {
        'Public': '#2ecc71',      # Green - Low risk
        'Internal': '#f1c40f',    # Yellow - Medium risk
        'Restricted': '#e67e22',  # Orange - High Risk
        'Critical': '#e74c3c',    # Red - Severe
        'Level 1': '#2ecc71',
        'Level 2': '#82e0aa',
        'Level 3': '#f1c40f',
        'Level 4': '#e67e22',
        'Level 5': '#e74c3c'
    }
    
    # Assign colors dynamically, defaulting to gray if not mapped
    marker_colors = [color_map.get(label, '#95a5a6') for label in labels]

    fig = go.Figure(data=[
        go.Bar(
            x=labels, 
            y=values,
            marker_color=marker_colors,
            text=values,
            textposition='auto',
            textfont=dict(color='white', size=16)
        )
    ])
    
    fig.update_layout(
        title=dict(text="Distribution of Sensitive Data Accessed by User", font=dict(size=18)),
        xaxis_title=dict(text="Sensitivity Level Classification", font=dict(size=14)),
        yaxis_title=dict(text="Number of Data Paths/Columns", font=dict(size=14)),
        template="plotly_white",
        margin=dict(t=60, b=40, l=40, r=40)
    )
    
    return fig


def generate_kpi_gauges(system_health_score, avg_user_risk_score):
    """
    Generates gauge charts using Plotly for 'System Health' and 'Average User Risk'.
    
    Args:
        system_health_score (float): Score out of 100 (higher is better).
        avg_user_risk_score (float): Average risk score across system users (lower is better).
        
    Returns:
        plotly.graph_objects.Figure: A Plotly figure containing two side-by-side gauge charts.
    """
    fig = go.Figure()

    # 1. System Health Gauge (Left)
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=system_health_score,
        domain={'x': [0, 0.45], 'y': [0, 1]},
        title={'text': "System Health (%)", 'font': {'size': 20}},
        number={'suffix': "%", 'font': {'size': 40}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "#2c3e50"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 50], 'color': "#ffcccb"},    # Red
                {'range': [50, 80], 'color': "#fff2cc"},   # Yellow
                {'range': [80, 100], 'color': "#d9ead3"}   # Green
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': system_health_score
            }
        }
    ))

    # 2. Average User Risk Gauge (Right)
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=avg_user_risk_score,
        domain={'x': [0.55, 1], 'y': [0, 1]},
        title={'text': "Average User Risk", 'font': {'size': 20}},
        number={'font': {'size': 40}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "#c0392b"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 25], 'color': "#d9ead3"},    # Green (Low risk)
                {'range': [25, 60], 'color': "#fff2cc"},   # Yellow (Med risk)
                {'range': [60, 100], 'color': "#ffcccb"}   # Red (High risk)
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': avg_user_risk_score
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#2c3e50", 'family': "Arial"},
        margin=dict(t=50, b=20, l=20, r=20)
    )

    return fig

# ==============================================================================
# Testing Block (Uncomment to test execution in an isolated environment)
# ==============================================================================
# if __name__ == '__main__':
#     # 1. Heatmap testing
#     df_mock = pd.DataFrame({
#         'HRIS': [12, 0, 1],
#         'ERP Financials': [2, 15, 0],
#         'IT Service Desk': [0, 2, 8]
#     }, index=['Human Resources', 'Finance', 'Information Technology'])
#     fig_hm = generate_risk_heatmap(df_mock)
#     plt.show()
#     
#     # 2. Impact Chart testing
#     impact_data = {'Public': 42, 'Internal': 27, 'Restricted': 15, 'Critical': 4}
#     fig_impact = generate_impact_chart(impact_data)
#     fig_impact.show()
#     
#     # 3. gauges testing
#     fig_kpi = generate_kpi_gauges(system_health_score=87.5, avg_user_risk_score=35.2)
#     fig_kpi.show()
