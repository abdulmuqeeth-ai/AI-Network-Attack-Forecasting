import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from src.preprocessing import load_data, extract_features
from src.detector import detect_anomalies, get_current_stage
from src.forecaster import forecast_next_stage
from src.mitre_mapper import map_to_mitre, ATTACK_CHAIN


st.set_page_config(page_title="Cyber Threat Forecasting", page_icon="🛡️", layout="wide")

st.title("🛡️ Cyber Threat Forecasting System")
st.caption("Network Traffic → Detect → Forecast → MITRE ATT&CK → Explain")


st.sidebar.header("📥 Data Input")
uploaded = st.sidebar.file_uploader("Upload network-flow CSV", type=["csv"])
use_sample = st.sidebar.checkbox("Use sample dataset", value=True)

if uploaded is not None:
    df_raw = load_data(uploaded)
    source = "Uploaded CSV"
elif use_sample:
    df_raw = load_data("data/sample_network_data.csv")
    source = "Sample dataset"
else:
    st.info("Upload a CSV or enable the sample dataset.")
    st.stop()

st.sidebar.success(f"Loaded: {source} ({len(df_raw)} flows)")


df = extract_features(df_raw)
df = detect_anomalies(df)

current_stage = get_current_stage(df)
mitre_now = map_to_mitre(current_stage)
avg_threat = int(df["threat_score"].mean())
forecast = forecast_next_stage(current_stage, avg_threat)
mitre_next = map_to_mitre(forecast["next_stage"])


col1, col2, col3 = st.columns(3)

with col1:
    status_icon = "🟢" if current_stage == "Benign" else "⚠️"
    st.metric("Network Status", f"{status_icon} {'NORMAL' if current_stage=='Benign' else 'SUSPICIOUS'}")
    st.metric("Current Stage", current_stage)

with col2:
    st.metric("🔮 Next Likely Stage", forecast["next_stage"])
    st.metric("Confidence", f"{forecast['confidence']}%")

with col3:
    st.metric("MITRE Technique", mitre_next["technique_id"])
    st.metric("Risk Level", mitre_next["risk"])

st.divider()

c1, c2 = st.columns(2)

with c1:
    st.subheader("🧩 Current MITRE ATT&CK")
    st.markdown(f"""
**Tactic:** {mitre_now['tactic']}  
**Technique:** `{mitre_now['technique_id']}` — {mitre_now['technique']}  
**Risk:** {mitre_now['risk']}  
**Why:** {mitre_now['description']}
""")

with c2:
    st.subheader("🔮 Forecasted MITRE ATT&CK")
    st.markdown(f"""
**Tactic:** {mitre_next['tactic']}  
**Technique:** `{mitre_next['technique_id']}` — {mitre_next['technique']}  
**Risk:** {mitre_next['risk']}  
**Why:** {mitre_next['description']}
""")

st.subheader("📊 Attack Progression Timeline")

current_idx = ATTACK_CHAIN.index(current_stage) if current_stage in ATTACK_CHAIN else -1
next_idx = ATTACK_CHAIN.index(forecast["next_stage"]) if forecast["next_stage"] in ATTACK_CHAIN else -1

fig = go.Figure()
for i, stage in enumerate(ATTACK_CHAIN):
    color = "#888"
    label = stage
    if i == current_idx:
        color = "#ff4b4b"
        label = f"{stage}  ← CURRENT"
    elif i == next_idx:
        color = "#ffa500"
        label = f"{stage}  🔮 FORECAST"
    elif current_idx >= 0 and i < current_idx:
        color = "#4b8bff"

    fig.add_trace(go.Scatter(
        x=[i], y=[0], mode="markers+text",
        marker=dict(size=40, color=color),
        text=[label], textposition="bottom center",
        showlegend=False,
        hoverinfo="text"
    ))

fig.update_layout(
    height=200,
    xaxis=dict(showgrid=False, showticklabels=False, range=[-0.5, len(ATTACK_CHAIN)-0.5]),
    yaxis=dict(showgrid=False, showticklabels=False, range=[-1, 1]),
    plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(l=20, r=20, t=20, b=40),
)
st.plotly_chart(fig, use_container_width=True)

st.subheader("🔍 Detected Flows")
display_cols = ["timestamp", "src_ip", "dst_ip", "dst_port",
                "protocol", "bytes_sent", "packets",
                "detected_stage", "threat_score"]
display_cols = [c for c in display_cols if c in df.columns]
st.dataframe(df[display_cols], use_container_width=True)

st.subheader("📈 Stage Distribution")
counts = df["detected_stage"].value_counts()
st.bar_chart(counts)