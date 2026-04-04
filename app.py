"""
IoMT Risk Assessment Tool
=========================
A healthcare cybersecurity risk scoring tool for Internet of Medical Things devices.

Score and prioritize your hospital's IoMT risks in 5 minutes.
Transparent, tunable, patient-safety focused.

Author: Nathan Mills
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import numpy as np

from scorer import (
    calculate_risk_score,
    score_dataframe,
    validate_csv,
    get_risk_level,
    DEFAULT_WEIGHTS,
    DEVICE_TYPES,
    NETWORK_SEGMENTS,
    OS_OPTIONS,
    PATCHABLE_OPTIONS,
    VENDOR_SUPPORT_OPTIONS,
    PHI_OPTIONS,
    FDA_CLASSES,
    AUTH_OPTIONS,
    ENCRYPTION_OPTIONS,
    REQUIRED_COLUMNS,
)
from controls import get_recommendations, get_priority_color
from report_generator import generate_report


# ── Page Config ─────────────────────────────────────────────────────

st.set_page_config(
    page_title="IoMT Risk Scorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ──────────────────────────────────────────────────────

st.markdown("""
<style>
    /* Main teal accent */
    :root {
        --teal: #20808D;
        --teal-dark: #1a6b76;
        --critical: #FF4B4B;
        --high: #FF8C00;
        --medium: #FFD700;
        --low: #20808D;
        --card-bg: #1A1D23;
        --surface: #0E1117;
    }

    /* Metric cards */
    .metric-card {
        background: var(--card-bg);
        border-radius: 10px;
        padding: 20px;
        border-left: 4px solid var(--teal);
        margin-bottom: 10px;
    }
    .metric-value {
        font-size: 2.4rem;
        font-weight: 700;
        color: #FAFAFA;
        line-height: 1.2;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8899A6;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 4px;
    }

    /* Risk badges */
    .risk-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .risk-critical { background: rgba(255, 75, 75, 0.2); color: #FF4B4B; border: 1px solid #FF4B4B; }
    .risk-high { background: rgba(255, 140, 0, 0.2); color: #FF8C00; border: 1px solid #FF8C00; }
    .risk-medium { background: rgba(255, 215, 0, 0.2); color: #FFD700; border: 1px solid #FFD700; }
    .risk-low { background: rgba(32, 128, 141, 0.2); color: #20808D; border: 1px solid #20808D; }

    /* Sub-score bar */
    .subscore-bar-bg {
        background: #2A2D35;
        border-radius: 6px;
        height: 14px;
        width: 100%;
        overflow: hidden;
    }
    .subscore-bar-fill {
        height: 100%;
        border-radius: 6px;
        transition: width 0.3s ease;
    }

    /* Control card */
    .control-card {
        background: var(--card-bg);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        border-left: 3px solid;
    }

    /* Sidebar branding */
    .sidebar-brand {
        font-size: 1.4rem;
        font-weight: 700;
        color: var(--teal);
        margin-bottom: 0.2rem;
    }
    .sidebar-tagline {
        font-size: 0.8rem;
        color: #8899A6;
        margin-bottom: 1.5rem;
    }

    /* Hide default Streamlit elements for cleaner look */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}

    /* Table styling */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 10px 20px;
    }
</style>
""", unsafe_allow_html=True)


# ── Session State Initialization ────────────────────────────────────

if "devices_df" not in st.session_state:
    st.session_state.devices_df = None
if "scored_df" not in st.session_state:
    st.session_state.scored_df = None
if "selected_device" not in st.session_state:
    st.session_state.selected_device = None
if "weights" not in st.session_state:
    st.session_state.weights = DEFAULT_WEIGHTS.copy()


# ── Helper Functions ────────────────────────────────────────────────

def risk_badge_html(level: str) -> str:
    css_class = f"risk-{level.lower()}"
    return f'<span class="risk-badge {css_class}">{level}</span>'


def metric_card(value, label, accent_color=None):
    color = accent_color or "var(--teal)"
    st.markdown(f"""
        <div class="metric-card" style="border-left-color: {color};">
            <div class="metric-value" style="color: {color};">{value}</div>
            <div class="metric-label">{label}</div>
        </div>
    """, unsafe_allow_html=True)


def subscore_bar(label: str, value: float, max_val: float = 100):
    pct = min(value / max_val * 100, 100)
    _, color = get_risk_level(value)
    st.markdown(f"""
        <div style="margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                <span style="font-size: 0.85rem; color: #CCCCCC;">{label}</span>
                <span style="font-size: 0.85rem; font-weight: 600; color: {color};">{value:.1f}</span>
            </div>
            <div class="subscore-bar-bg">
                <div class="subscore-bar-fill" style="width: {pct}%; background: {color};"></div>
            </div>
        </div>
    """, unsafe_allow_html=True)


def score_devices():
    """Score all devices with current weights."""
    if st.session_state.devices_df is not None and len(st.session_state.devices_df) > 0:
        st.session_state.scored_df = score_dataframe(
            st.session_state.devices_df.copy(),
            st.session_state.weights,
        )


# ── Sidebar ─────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<div class="sidebar-brand">🛡️ IoMT Risk Scorer</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-tagline">Healthcare IoMT Cybersecurity Risk Assessment</div>', unsafe_allow_html=True)

    page = st.radio(
        "Navigation",
        ["📋 Device Inventory", "📊 Risk Dashboard", "🔍 Device Detail", "📄 Assessment Report"],
        label_visibility="collapsed",
    )

    st.divider()

    # Weight tuning
    st.markdown("**⚙️ Risk Weight Tuning**")
    st.caption("Adjust weights to reflect your organization's risk priorities.")

    w_exposure = st.slider("Exposure", 0.0, 1.0, st.session_state.weights["exposure"], 0.05, key="w_exp")
    w_vuln = st.slider("Vulnerability", 0.0, 1.0, st.session_state.weights["vulnerability"], 0.05, key="w_vul")
    w_data = st.slider("Data Sensitivity", 0.0, 1.0, st.session_state.weights["data_sensitivity"], 0.05, key="w_dat")
    w_safety = st.slider("Patient Safety", 0.0, 1.0, st.session_state.weights["patient_safety"], 0.05, key="w_saf")
    w_auth = st.slider("Authentication", 0.0, 1.0, st.session_state.weights["authentication"], 0.05, key="w_aut")

    new_weights = {
        "exposure": w_exposure,
        "vulnerability": w_vuln,
        "data_sensitivity": w_data,
        "patient_safety": w_safety,
        "authentication": w_auth,
    }

    if new_weights != st.session_state.weights:
        st.session_state.weights = new_weights
        score_devices()

    total_w = sum(new_weights.values())
    if total_w > 0:
        st.caption(f"Weights normalize to 100%. Current sum: {total_w:.2f}")
    else:
        st.warning("All weights are zero!")

    st.divider()
    st.caption("Built by Nathan Mills")
    st.caption("Security+ Certified")


# ── Page: Device Inventory ──────────────────────────────────────────

if page == "📋 Device Inventory":
    st.markdown("# 📋 Device Inventory")
    st.markdown("Upload a CSV of your hospital's IoMT devices or add them manually.")

    tab_upload, tab_manual, tab_sample = st.tabs(["📁 Upload CSV", "✏️ Add Manually", "📦 Load Sample Data"])

    with tab_upload:
        st.markdown("**Upload a CSV file** with your device inventory. Required columns:")
        with st.expander("View required CSV columns"):
            for col in REQUIRED_COLUMNS:
                st.markdown(f"- `{col}`")

        uploaded = st.file_uploader("Choose CSV file", type=["csv"], key="csv_upload")
        if uploaded is not None:
            try:
                df = pd.read_csv(uploaded)
                errors = validate_csv(df)
                if errors:
                    for e in errors:
                        st.error(f"⚠️ {e}")
                else:
                    st.session_state.devices_df = df
                    score_devices()
                    st.success(f"✅ Loaded {len(df)} devices successfully!")
            except Exception as e:
                st.error(f"Error reading CSV: {e}")

    with tab_manual:
        st.markdown("**Add a single device** to the inventory.")

        with st.form("add_device_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                d_name = st.text_input("Device Name *", placeholder="ICU Ventilator #3")
                d_type = st.selectbox("Device Type *", DEVICE_TYPES)
                d_mfr = st.text_input("Manufacturer / Model", placeholder="Hamilton Medical C6")
                d_net = st.selectbox("Network Segment *", NETWORK_SEGMENTS)
                d_os = st.selectbox("OS/Firmware *", OS_OPTIONS)
                d_patch = st.selectbox("Patchable *", PATCHABLE_OPTIONS)

            with col2:
                d_vendor = st.selectbox("Vendor Support Status *", VENDOR_SUPPORT_OPTIONS)
                d_phi = st.selectbox("PHI Handling *", PHI_OPTIONS)
                d_fda = st.selectbox("FDA Class *", FDA_CLASSES)
                d_scan = st.date_input("Last Vulnerability Scan", value=None)
                d_auth = st.selectbox("Authentication *", AUTH_OPTIONS)
                d_enc = st.selectbox("Encryption *", ENCRYPTION_OPTIONS)

            submitted = st.form_submit_button("➕ Add Device", use_container_width=True)

            if submitted:
                if not d_name.strip():
                    st.error("Device Name is required.")
                else:
                    new_device = {
                        "Device Name": d_name.strip(),
                        "Device Type": d_type,
                        "Manufacturer / Model": d_mfr.strip(),
                        "Network Segment": d_net,
                        "OS/Firmware": d_os,
                        "Patchable": d_patch,
                        "Vendor Support Status": d_vendor,
                        "PHI Handling": d_phi,
                        "FDA Class": d_fda,
                        "Last Vulnerability Scan": str(d_scan) if d_scan else "",
                        "Authentication": d_auth,
                        "Encryption": d_enc,
                    }
                    new_row = pd.DataFrame([new_device])
                    if st.session_state.devices_df is None:
                        st.session_state.devices_df = new_row
                    else:
                        st.session_state.devices_df = pd.concat(
                            [st.session_state.devices_df, new_row], ignore_index=True
                        )
                    score_devices()
                    st.success(f"✅ Added '{d_name}' to inventory!")

    with tab_sample:
        st.markdown("**Load sample data** with 25 realistic hospital IoMT devices across ICU, ER, Radiology, Lab, General Ward, and Building Systems.")
        if st.button("🔄 Load Sample Devices", use_container_width=True):
            try:
                df = pd.read_csv("sample_devices.csv")
                st.session_state.devices_df = df
                score_devices()
                st.success(f"✅ Loaded {len(df)} sample devices!")
            except FileNotFoundError:
                st.error("sample_devices.csv not found. Please ensure it's in the app directory.")

    # Display current inventory
    st.divider()
    if st.session_state.scored_df is not None and len(st.session_state.scored_df) > 0:
        df_display = st.session_state.scored_df.copy()

        st.markdown(f"### Current Inventory ({len(df_display)} devices)")

        # Summary badges
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            crit = len(df_display[df_display["risk_level"] == "Critical"])
            metric_card(crit, "Critical", "#FF4B4B")
        with col2:
            high = len(df_display[df_display["risk_level"] == "High"])
            metric_card(high, "High", "#FF8C00")
        with col3:
            med = len(df_display[df_display["risk_level"] == "Medium"])
            metric_card(med, "Medium", "#FFD700")
        with col4:
            low = len(df_display[df_display["risk_level"] == "Low"])
            metric_card(low, "Low", "#20808D")

        # Inventory table
        show_cols = [
            "Device Name", "Device Type", "Manufacturer / Model",
            "Network Segment", "total_score", "risk_level",
        ]
        available = [c for c in show_cols if c in df_display.columns]
        table_df = df_display[available].sort_values("total_score", ascending=False)
        table_df = table_df.rename(columns={
            "total_score": "Risk Score",
            "risk_level": "Risk Level",
        })

        st.dataframe(
            table_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%.1f",
                ),
            },
        )

        # Clear button
        if st.button("🗑️ Clear All Devices"):
            st.session_state.devices_df = None
            st.session_state.scored_df = None
            st.session_state.selected_device = None
            st.rerun()
    else:
        st.info("No devices loaded yet. Upload a CSV, add devices manually, or load sample data above.")


# ── Page: Risk Dashboard ───────────────────────────────────────────

elif page == "📊 Risk Dashboard":
    st.markdown("# 📊 Risk Dashboard")

    if st.session_state.scored_df is None or len(st.session_state.scored_df) == 0:
        st.warning("No devices loaded. Go to Device Inventory to add devices first.")
    else:
        df = st.session_state.scored_df.copy()

        # ── Summary Metrics ──
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            metric_card(len(df), "Total Devices", "#20808D")
        with col2:
            avg = df["total_score"].mean()
            _, avg_color = get_risk_level(avg)
            metric_card(f"{avg:.1f}", "Avg Risk Score", avg_color)
        with col3:
            crit = len(df[df["risk_level"] == "Critical"])
            metric_card(crit, "Critical Devices", "#FF4B4B")
        with col4:
            high = len(df[df["risk_level"].isin(["Critical", "High"])])
            metric_card(high, "Critical + High", "#FF8C00")

        st.divider()

        # ── Charts Row 1 ──
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown("### Risk Distribution")
            risk_counts = df["risk_level"].value_counts().reindex(
                ["Critical", "High", "Medium", "Low"], fill_value=0
            )
            fig = go.Figure(data=[
                go.Bar(
                    x=risk_counts.index,
                    y=risk_counts.values,
                    marker_color=["#FF4B4B", "#FF8C00", "#FFD700", "#20808D"],
                    text=risk_counts.values,
                    textposition="auto",
                    textfont=dict(size=14, color="white"),
                )
            ])
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(26,29,35,0.8)",
                xaxis_title="Risk Level",
                yaxis_title="Device Count",
                height=350,
                margin=dict(l=40, r=20, t=20, b=40),
                font=dict(color="#CCCCCC"),
            )
            st.plotly_chart(fig, use_container_width=True)

        with chart_col2:
            st.markdown("### Score Distribution")
            fig = go.Figure(data=[
                go.Histogram(
                    x=df["total_score"],
                    nbinsx=20,
                    marker_color="#20808D",
                    marker_line_color="#1a6b76",
                    marker_line_width=1,
                )
            ])
            fig.add_vline(x=75, line_dash="dash", line_color="#FF4B4B", annotation_text="Critical")
            fig.add_vline(x=50, line_dash="dash", line_color="#FF8C00", annotation_text="High")
            fig.add_vline(x=25, line_dash="dash", line_color="#FFD700", annotation_text="Medium")
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(26,29,35,0.8)",
                xaxis_title="Risk Score",
                yaxis_title="Count",
                height=350,
                margin=dict(l=40, r=20, t=20, b=40),
                font=dict(color="#CCCCCC"),
            )
            st.plotly_chart(fig, use_container_width=True)

        # ── Heatmap ──
        st.markdown("### Risk Heatmap: Device Type × Network Segment")
        heatmap_data = df.pivot_table(
            values="total_score",
            index="Device Type",
            columns="Network Segment",
            aggfunc="mean",
        ).fillna(0)

        # Reorder columns for logical display
        col_order = [c for c in ["Air-Gapped", "Clinical VLAN", "DMZ", "Flat Network", "Guest WiFi", "Internet-Facing"] if c in heatmap_data.columns]
        heatmap_data = heatmap_data[col_order] if col_order else heatmap_data

        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns,
            y=heatmap_data.index,
            colorscale=[
                [0, "#0E3B43"],
                [0.25, "#20808D"],
                [0.5, "#FFD700"],
                [0.75, "#FF8C00"],
                [1, "#FF4B4B"],
            ],
            zmin=0,
            zmax=100,
            text=np.round(heatmap_data.values, 1),
            texttemplate="%{text}",
            textfont={"size": 11, "color": "white"},
            hovertemplate="Type: %{y}<br>Network: %{x}<br>Avg Score: %{z:.1f}<extra></extra>",
            colorbar=dict(title="Risk Score"),
        ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(26,29,35,0.8)",
            height=max(300, len(heatmap_data) * 45 + 100),
            margin=dict(l=20, r=20, t=20, b=40),
            font=dict(color="#CCCCCC"),
            xaxis=dict(side="bottom"),
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── Top 10 Riskiest ──
        st.markdown("### Top 10 Riskiest Devices")
        top10 = df.nlargest(10, "total_score")
        fig = go.Figure(data=[
            go.Bar(
                y=top10["Device Name"],
                x=top10["total_score"],
                orientation="h",
                marker_color=[get_risk_level(s)[1] for s in top10["total_score"]],
                text=[f"{s:.1f}" for s in top10["total_score"]],
                textposition="auto",
                textfont=dict(color="white", size=12),
            )
        ])
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(26,29,35,0.8)",
            xaxis_title="Risk Score",
            xaxis=dict(range=[0, 105]),
            height=max(300, len(top10) * 40 + 60),
            margin=dict(l=20, r=20, t=10, b=40),
            font=dict(color="#CCCCCC"),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── Sub-Score Radar ──
        st.markdown("### Average Sub-Scores Across All Devices")
        avg_subscores = {
            "Exposure": df["exposure_score"].mean(),
            "Vulnerability": df["vulnerability_score"].mean(),
            "Data Sensitivity": df["data_sensitivity_score"].mean(),
            "Patient Safety": df["patient_safety_score"].mean(),
            "Authentication": df["authentication_score"].mean(),
        }
        categories = list(avg_subscores.keys())
        values = list(avg_subscores.values())

        fig = go.Figure(data=go.Scatterpolar(
            r=values + [values[0]],
            theta=categories + [categories[0]],
            fill="toself",
            fillcolor="rgba(32, 128, 141, 0.3)",
            line=dict(color="#20808D", width=2),
            marker=dict(size=6, color="#20808D"),
        ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100],
                    gridcolor="rgba(255,255,255,0.1)",
                ),
                angularaxis=dict(gridcolor="rgba(255,255,255,0.1)"),
                bgcolor="rgba(26,29,35,0.8)",
            ),
            height=400,
            margin=dict(l=60, r=60, t=40, b=40),
            font=dict(color="#CCCCCC"),
        )
        st.plotly_chart(fig, use_container_width=True)


# ── Page: Device Detail ────────────────────────────────────────────

elif page == "🔍 Device Detail":
    st.markdown("# 🔍 Device Detail")

    if st.session_state.scored_df is None or len(st.session_state.scored_df) == 0:
        st.warning("No devices loaded. Go to Device Inventory to add devices first.")
    else:
        df = st.session_state.scored_df

        # Device selector
        device_names = df["Device Name"].tolist()
        selected = st.selectbox(
            "Select a device",
            device_names,
            index=0,
            key="device_selector",
        )

        device_row = df[df["Device Name"] == selected].iloc[0]
        device = device_row.to_dict()
        score = device.get("total_score", 0)
        level = device.get("risk_level", "Unknown")
        _, level_color = get_risk_level(score)

        # ── Header ──
        header_col1, header_col2 = st.columns([3, 1])
        with header_col1:
            st.markdown(f"## {selected}")
            st.markdown(
                f'{risk_badge_html(level)} &nbsp; '
                f'**{device.get("Device Type", "")}** · '
                f'{device.get("Manufacturer / Model", "")}',
                unsafe_allow_html=True,
            )
        with header_col2:
            st.markdown(f"""
                <div style="text-align: center; padding: 10px;">
                    <div style="font-size: 3rem; font-weight: 800; color: {level_color};">{score:.1f}</div>
                    <div style="font-size: 0.85rem; color: #8899A6;">RISK SCORE</div>
                </div>
            """, unsafe_allow_html=True)

        st.divider()

        # ── Device Properties ──
        st.markdown("### Device Properties")
        prop_col1, prop_col2, prop_col3 = st.columns(3)
        with prop_col1:
            st.markdown(f"**Network Segment:** {device.get('Network Segment', 'N/A')}")
            st.markdown(f"**OS/Firmware:** {device.get('OS/Firmware', 'N/A')}")
            st.markdown(f"**Patchable:** {device.get('Patchable', 'N/A')}")
            st.markdown(f"**Vendor Support:** {device.get('Vendor Support Status', 'N/A')}")
        with prop_col2:
            st.markdown(f"**PHI Handling:** {device.get('PHI Handling', 'N/A')}")
            st.markdown(f"**FDA Class:** {device.get('FDA Class', 'N/A')}")
            st.markdown(f"**Authentication:** {device.get('Authentication', 'N/A')}")
            st.markdown(f"**Encryption:** {device.get('Encryption', 'N/A')}")
        with prop_col3:
            scan = device.get("Last Vulnerability Scan", "")
            scan_display = scan if scan and str(scan).strip() not in ("", "nan", "NaT") else "Never"
            st.markdown(f"**Last Vuln Scan:** {scan_display}")

        st.divider()

        # ── Sub-Score Breakdown ──
        st.markdown("### Risk Score Breakdown")
        sub_col1, sub_col2 = st.columns([2, 1])

        with sub_col1:
            subscore_bar("Exposure", device.get("exposure_score", 0))
            subscore_bar("Vulnerability", device.get("vulnerability_score", 0))
            subscore_bar("Data Sensitivity", device.get("data_sensitivity_score", 0))
            subscore_bar("Patient Safety", device.get("patient_safety_score", 0))
            subscore_bar("Authentication", device.get("authentication_score", 0))

        with sub_col2:
            # Radar chart for this device
            subscores = {
                "Exposure": device.get("exposure_score", 0),
                "Vulnerability": device.get("vulnerability_score", 0),
                "Data Sensitivity": device.get("data_sensitivity_score", 0),
                "Patient Safety": device.get("patient_safety_score", 0),
                "Authentication": device.get("authentication_score", 0),
            }
            cats = list(subscores.keys())
            vals = list(subscores.values())

            fig = go.Figure(data=go.Scatterpolar(
                r=vals + [vals[0]],
                theta=cats + [cats[0]],
                fill="toself",
                fillcolor=f"rgba({int(level_color[1:3], 16)}, {int(level_color[3:5], 16)}, {int(level_color[5:7], 16)}, 0.3)",
                line=dict(color=level_color, width=2),
            ))
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100], gridcolor="rgba(255,255,255,0.1)"),
                    angularaxis=dict(gridcolor="rgba(255,255,255,0.1)"),
                    bgcolor="rgba(26,29,35,0.8)",
                ),
                height=280,
                margin=dict(l=40, r=40, t=20, b=20),
                font=dict(color="#CCCCCC", size=10),
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)

        st.divider()

        # ── Recommended Controls ──
        st.markdown("### Recommended Controls")
        recs = get_recommendations(device)

        if not recs:
            st.success("No critical recommendations for this device. Maintain current posture.")
        else:
            for rec in recs:
                p_color = get_priority_color(rec["priority"])
                with st.container():
                    st.markdown(f"""
                        <div class="control-card" style="border-left-color: {p_color};">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <span style="font-weight: 600; font-size: 0.95rem; color: #FAFAFA;">{rec['title']}</span>
                                <span class="risk-badge" style="background: rgba({int(p_color[1:3], 16)}, {int(p_color[3:5], 16)}, {int(p_color[5:7], 16)}, 0.2); color: {p_color}; border: 1px solid {p_color};">{rec['priority']}</span>
                            </div>
                            <p style="color: #AAAAAA; font-size: 0.85rem; margin-bottom: 8px;">{rec['description']}</p>
                            <div style="font-size: 0.75rem; color: #20808D;">
                                📋 {rec['nist_csf']}<br>
                                🏥 HIPAA {rec['hipaa']}<br>
                                📁 Category: {rec['category']}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)


# ── Page: Assessment Report ─────────────────────────────────────────

elif page == "📄 Assessment Report":
    st.markdown("# 📄 Assessment Report")
    st.markdown("Generate a downloadable PDF risk assessment report with executive summary, "
                "device inventory, risk findings, and prioritized remediation plan.")

    if st.session_state.scored_df is None or len(st.session_state.scored_df) == 0:
        st.warning("No devices loaded. Go to Device Inventory to add devices first.")
    else:
        df = st.session_state.scored_df

        st.markdown("### Report Configuration")
        col1, col2 = st.columns(2)
        with col1:
            org_name = st.text_input("Organization Name", "General Hospital", key="org_name")
        with col2:
            assessor_name = st.text_input("Assessor Name", "Nathan Mills", key="assessor_name")

        st.divider()

        # Report preview
        st.markdown("### Report Preview")
        preview_col1, preview_col2, preview_col3, preview_col4 = st.columns(4)

        total = len(df)
        crit = len(df[df["risk_level"] == "Critical"])
        high = len(df[df["risk_level"] == "High"])
        avg = df["total_score"].mean()

        with preview_col1:
            metric_card(total, "Devices in Report", "#20808D")
        with preview_col2:
            metric_card(f"{avg:.1f}", "Avg Risk Score", "#FF8C00" if avg >= 50 else "#20808D")
        with preview_col3:
            metric_card(crit, "Critical Findings", "#FF4B4B")
        with preview_col4:
            metric_card(crit + high, "Action Items", "#FF8C00")

        st.markdown("### Report Contents")
        st.markdown("""
        The generated report will include:
        1. **Executive Summary** — High-level risk posture overview with key metrics
        2. **Methodology** — Scoring approach, weight configuration, and framework references
        3. **Device Inventory** — Full inventory table sorted by risk score
        4. **Risk Findings & Recommendations** — Per-device risk breakdown with sub-scores and
           actionable controls mapped to NIST CSF and HIPAA Security Rule
        5. **Prioritized Remediation Plan** — Devices grouped by risk level with recommended timelines
        6. **Framework References** — Full citations with URLs for all referenced standards
        """)

        st.divider()

        # Generate button
        if st.button("📥 Generate PDF Report", use_container_width=True, type="primary"):
            with st.spinner("Generating report..."):
                try:
                    pdf_bytes = generate_report(df, org_name, assessor_name)
                    st.success("✅ Report generated successfully!")
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"iomt_risk_assessment_{datetime.now().strftime('%Y%m%d')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"Error generating report: {e}")
                    st.exception(e)

        # Methodology reference
        st.divider()
        st.markdown("### Methodology Reference")

        with st.expander("📚 Framework Citations"):
            st.markdown("""
            **NIST SP 800-30 Rev. 1** — Guide for Conducting Risk Assessments
            > Provides the foundational risk assessment methodology: threat identification,
            > vulnerability analysis, likelihood determination, and impact analysis.
            > [csrc.nist.gov/publications/detail/sp/800-30/rev-1/final](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)

            **NIST Cybersecurity Framework 2.0**
            > Control function taxonomy (Identify, Protect, Detect, Respond, Recover, Govern)
            > used to categorize all recommended controls.
            > [nist.gov/cyberframework](https://www.nist.gov/cyberframework)

            **FDA Premarket Cybersecurity Guidance (September 2023)**
            > Informs patient safety scoring and FDA class-based risk tiering.
            > [fda.gov/regulatory-information/search-fda-guidance-documents](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions)

            **HHS 405(d) Health Industry Cybersecurity Practices (HICP)**
            > Healthcare-specific cybersecurity practices informing recommended controls.
            > [405d.hhs.gov](https://405d.hhs.gov/)

            **HIPAA Security Rule (45 CFR §164.308-312)**
            > Administrative, physical, and technical safeguards for ePHI.
            > [hhs.gov/hipaa/for-professionals/security](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
            """)

        with st.expander("⚙️ Scoring Formula"):
            st.markdown("""
            ```
            RISK_SCORE = (
                Exposure_Score      × 0.20 +    # Network segment exposure
                Vulnerability_Score × 0.20 +    # Patchability + vendor support + OS age
                Data_Sensitivity    × 0.20 +    # PHI handling level
                Patient_Safety      × 0.25 +    # FDA class × device criticality
                Authentication      × 0.15      # Auth method × encryption posture
            )
            ```

            Each sub-score ranges from 0-100. Weights are user-tunable in the sidebar.
            The composite score maps to risk levels: **Critical** (75-100), **High** (50-74),
            **Medium** (25-49), **Low** (0-24).
            """)
