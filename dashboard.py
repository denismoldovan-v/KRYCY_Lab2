import json
import os
from datetime import datetime

import pandas as pd
import streamlit as st
import plotly.express as px

OUT_DEFAULT = "out"

st.set_page_config(
    page_title="NetPoC Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Netflix-ish styling (dark + cards) ---
st.markdown(
    """
    <style>
      .block-container { padding-top: 1.2rem; padding-bottom: 1.2rem; }
      html, body, [class*="css"]  { background-color: #0b0f19; color: #e6e6e6; }
      section[data-testid="stSidebar"] { background-color: #0f1629; }
      .kpi-card {
        background: #0f1629;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 18px;
        padding: 14px 16px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.35);
      }
      .kpi-title { font-size: 0.85rem; opacity: 0.8; margin-bottom: 4px; }
      .kpi-value { font-size: 1.6rem; font-weight: 700; }
      .muted { opacity: 0.7; }
      .pill {
        display: inline-block; padding: 3px 10px; border-radius: 999px;
        background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);
        font-size: 0.8rem;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_json(path: str):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_read_csv(path: str):
    if not os.path.exists(path):
        return None
    return pd.read_csv(path)


def ms_to_dt(ms: int):
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0)
    except Exception:
        return None


# --- Sidebar ---
st.sidebar.title("NetPoC")
out_dir = st.sidebar.text_input("Output folder", OUT_DEFAULT)

alerts_path = os.path.join(out_dir, "alerts.json")
flows_path = os.path.join(out_dir, "flows.csv")
pairs_path = os.path.join(out_dir, "pairs_summary.csv")
ml_path = os.path.join(out_dir, "ml_predictions.csv")
map_path = os.path.join(out_dir, "map.html")

alerts = load_json(alerts_path)
flows = safe_read_csv(flows_path)
pairs = safe_read_csv(pairs_path)
ml = safe_read_csv(ml_path)

st.sidebar.markdown("---")
st.sidebar.markdown("**Data sources**")
st.sidebar.write("alerts:", "✅" if os.path.exists(alerts_path) else "❌")
st.sidebar.write("flows:", "✅" if os.path.exists(flows_path) else "❌")
st.sidebar.write("pairs:", "✅" if os.path.exists(pairs_path) else "❌")
st.sidebar.write("ml:", "✅" if os.path.exists(ml_path) else "❌")
st.sidebar.write("map:", "✅" if os.path.exists(map_path) else "❌")

# --- Header ---
st.markdown("## 🎬 NetPoC Dashboard")
st.markdown('<span class="pill">dark mode</span>  <span class="pill">flows</span>  <span class="pill">sigma + python rules</span>  <span class="pill">ml</span>', unsafe_allow_html=True)

# --- Filters ---
rule_ids = sorted({a.get("rule_id", "UNKNOWN") for a in alerts}) if alerts else []
src_ips = sorted({a.get("src_ip", "") for a in alerts if a.get("src_ip")}) if alerts else []
dst_ips = sorted({a.get("dst_ip", "") for a in alerts if a.get("dst_ip")}) if alerts else []

colF1, colF2, colF3, colF4 = st.columns([1.2, 1, 1, 1])
with colF1:
    sel_rules = st.multiselect("Filter: rule_id", rule_ids, default=rule_ids[:10] if rule_ids else [])
with colF2:
    sel_src = st.multiselect("Filter: src_ip", src_ips, default=[])
with colF3:
    sel_dst = st.multiselect("Filter: dst_ip", dst_ips, default=[])
with colF4:
    bin_sec = st.selectbox("Timeline bin", [5, 10, 30, 60], index=3)

# Apply filters
flt = alerts
if sel_rules:
    flt = [a for a in flt if a.get("rule_id") in sel_rules]
if sel_src:
    flt = [a for a in flt if a.get("src_ip") in sel_src]
if sel_dst:
    flt = [a for a in flt if a.get("dst_ip") in sel_dst]

# --- KPIs ---
total_alerts = len(alerts)
filtered_alerts = len(flt)
total_flows = len(flows) if flows is not None else 0

sigma_count = sum(1 for a in alerts if str(a.get("rule_id", "")).upper().startswith("SIGMA"))
python_count = total_alerts - sigma_count

ml_on = ml is not None and len(ml) > 0
ml_susp = int((ml["pred_label"] == 1).sum()) if ml_on and "pred_label" in ml.columns else None

k1, k2, k3, k4, k5 = st.columns(5)
k1.markdown(f'<div class="kpi-card"><div class="kpi-title">Total flows</div><div class="kpi-value">{total_flows}</div></div>', unsafe_allow_html=True)
k2.markdown(f'<div class="kpi-card"><div class="kpi-title">Total alerts</div><div class="kpi-value">{total_alerts}</div></div>', unsafe_allow_html=True)
k3.markdown(f'<div class="kpi-card"><div class="kpi-title">Filtered alerts</div><div class="kpi-value">{filtered_alerts}</div></div>', unsafe_allow_html=True)
k4.markdown(f'<div class="kpi-card"><div class="kpi-title">Sigma vs Python</div><div class="kpi-value">{sigma_count} / {python_count}</div></div>', unsafe_allow_html=True)
k5.markdown(
    f'<div class="kpi-card"><div class="kpi-title">ML suspicious</div><div class="kpi-value">{ml_susp if ml_susp is not None else "—"}</div></div>',
    unsafe_allow_html=True
)

st.markdown("---")

# --- Timeline (bin seconds) ---
left, right = st.columns([1.35, 1])

with left:
    st.markdown("### ⏱️ Alerts timeline")
    if flt:
        dfA = pd.DataFrame(flt)
        # pick best timestamp field
        if "ts_ms" in dfA.columns and dfA["ts_ms"].notna().any():
            dfA["ts"] = dfA["ts_ms"].apply(ms_to_dt)
        else:
            # if no timestamps, fake a single timestamp so UI still works
            dfA["ts"] = datetime.now()
        dfA = dfA[dfA["ts"].notna()]
        dfA["bin"] = dfA["ts"].dt.floor(f"{bin_sec}S")
        g = dfA.groupby(["bin", "rule_id"]).size().reset_index(name="count")
        g = g.sort_values("bin")
        fig = px.line(g, x="bin", y="count", color="rule_id", title=None)
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend_title_text="rule_id",
            height=360,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Brak alertów po filtrach albo brak alerts.json.")

with right:
    st.markdown("### 🚨 Alert feed (latest)")
    if flt:
        dfA = pd.DataFrame(flt)
        if "ts_ms" in dfA.columns and dfA["ts_ms"].notna().any():
            dfA["ts"] = dfA["ts_ms"].apply(ms_to_dt)
            dfA = dfA.sort_values("ts", ascending=False)
        dfA = dfA.head(15)

        for _, row in dfA.iterrows():
            rid = row.get("rule_id", "UNKNOWN")
            sip = row.get("src_ip", "")
            dip = row.get("dst_ip", "")
            dpt = row.get("dst_port", "")
            det = row.get("details", "")
            st.markdown(
                f"""
                <div class="kpi-card" style="margin-bottom:10px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div><b>{rid}</b></div>
                    <div class="muted">{sip} ➜ {dip}:{dpt}</div>
                  </div>
                  <div class="muted" style="margin-top:6px;">{det}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.info("Brak alertów do wyświetlenia.")

st.markdown("---")

# --- Top talkers & pairs ---
c1, c2 = st.columns([1.1, 1])

with c1:
    st.markdown("### 🧠 Top host↔host (by bytes)")
    if pairs is not None and len(pairs) > 0:
        # Try common columns
        cols = pairs.columns.tolist()
        # Make a best-effort label
        src_col = "src_ip" if "src_ip" in cols else cols[0]
        dst_col = "dst_ip" if "dst_ip" in cols else cols[1]
        bytes_col = "bytes" if "bytes" in cols else ("total_bytes" if "total_bytes" in cols else cols[-1])

        top = pairs.head(15).copy()
        top["pair"] = top[src_col].astype(str) + " → " + top[dst_col].astype(str)
        fig = px.bar(top[::-1], x=bytes_col, y="pair", orientation="h", title=None)
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=380,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Brak pairs_summary.csv albo pusty plik.")

with c2:
    st.markdown("### 🤖 ML predictions (distribution)")
    if ml_on:
        # expecting pred_label and/or pred_score
        if "pred_label" in ml.columns:
            dist = ml["pred_label"].value_counts().reset_index()
            dist.columns = ["pred_label", "count"]
            fig = px.pie(dist, names="pred_label", values="count", title=None)
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                height=380,
                margin=dict(l=10, r=10, t=10, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.write(ml.head(20))
    else:
        st.info("Brak ml_predictions.csv (uruchom analyze z ML).")

st.markdown("---")

# --- Map embed ---
st.markdown("### 🗺️ Map (optional)")
if os.path.exists(map_path):
    with open(map_path, "r", encoding="utf-8") as f:
        html = f.read()
    st.components.v1.html(html, height=520, scrolling=True)
else:
    st.info("Brak map.html (enrichment mógł nie zwrócić geolokacji, albo wyłączyłeś mapę).")
