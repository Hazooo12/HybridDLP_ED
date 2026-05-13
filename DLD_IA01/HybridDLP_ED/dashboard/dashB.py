import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
import altair as alt
from streamlit_autorefresh import st_autorefresh
import streamlit.components.v1 as components

# ================= CONFIG =================
st.set_page_config(
    page_title="Hybrid DLP Security Center",
    page_icon="[SEC]",
    layout="wide"
)

# Auto refresh
st_autorefresh(interval=2000, key="refresh")

# ================= CSS =================
st.markdown("""
<style>
div[data-testid="metric-container"] {
    background-color: #f0f2f6;
    border-radius: 10px;
    padding: 10px;
    border: 1px solid #dcdcdc;
}
.main-title {
    font-size: 40px;
    font-weight: bold;
    color: #1E3A8A;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ================= PATH =================
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")
ALERT_WINDOW_MIN_SCORE = float(os.getenv("DASHBOARD_ALERT_WINDOW_MIN_SCORE", "7.0"))

# ================= LOAD DATA =================
def load_data():
    # Ensure dashboard log path always exists in local runs.
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False)
        except Exception as e:
            st.error(f"[FAIL] Không thể khởi tạo log file: {e}")
            return pd.DataFrame()

        st.info(
            "ℹ Chưa có dữ liệu cảnh báo. "
            "Hãy chạy Worker + Agent và tạo 1 sự kiện để dashboard cập nhật."
        )
        return pd.DataFrame()

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not data:
            st.warning("⚠ Log file is empty")
            return pd.DataFrame()

        df = pd.DataFrame(data)
        
        # Debug info
        file_mtime = os.path.getmtime(LOG_FILE) if os.path.exists(LOG_FILE) else 0
        file_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
        st.sidebar.text(f" File: {os.path.basename(LOG_FILE)}")
        st.sidebar.text(f"[DATA] Total rows: {len(df)}")
        st.sidebar.text(f" Modified: {datetime.fromtimestamp(file_mtime).strftime('%H:%M:%S') if file_mtime > 0 else 'N/A'}")
        st.sidebar.text(f" Size: {file_size:,} bytes")

        if not df.empty:
            # Parse timestamp với format ISO8601 (hỗ trợ nhiều format)
            # Use utc=True to avoid FutureWarning about mixed timezones
            df["timestamp"] = pd.to_datetime(df["timestamp"], format='ISO8601', errors='coerce', utc=True)
            # Remove rows với invalid timestamp
            df = df.dropna(subset=['timestamp'])
            # Ensure timestamp is datetime type
            if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
                df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce', utc=True)
                df = df.dropna(subset=['timestamp'])
            
            # Convert action to lowercase if it exists
            if "action" in df.columns:
                df["action"] = df["action"].str.lower()
            
            # Debug: show actions and risk scores
            if "action" in df.columns:
                st.sidebar.text(f" Actions: {df['action'].value_counts().to_dict()}")
            if "risk_score" in df.columns:
                st.sidebar.text(f" Risk range: {df['risk_score'].min()}-{df['risk_score'].max()}")

        return df

    except json.JSONDecodeError as e:
        st.error(f"[FAIL] JSON decode error: {e}")
        st.error(f"File: {LOG_FILE}")
        return pd.DataFrame()
    except Exception as e:
        st.error(f"[FAIL] Lỗi đọc log: {e}")
        import traceback
        st.error(f"Traceback: {traceback.format_exc()}")
        return pd.DataFrame()

# ================= SEVERITY (risk_score thang 0–10 = CVSS Severity) =================
def classify_severity(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "None"
    if s <= 0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"

# ================= UI =================
st.markdown('<div class="main-title">[SEC] HYBRID DLP - SECURITY CENTER</div>', unsafe_allow_html=True)
st.divider()

df = load_data()


def notify_browser(title: str, message: str):
    """Browser popup notification (works in Docker via dashboard tab)."""
    safe_title = json.dumps(title)
    safe_message = json.dumps(message)
    components.html(
        f"""
        <script>
        (function() {{
          const title = {safe_title};
          const message = {safe_message};
          if (!("Notification" in window)) return;
          const show = () => {{
            try {{ new Notification(title, {{ body: message }}); }} catch (e) {{}}
          }};
          if (Notification.permission === "granted") {{
            show();
          }} else if (Notification.permission !== "denied") {{
            Notification.requestPermission().then((p) => {{
              if (p === "granted") show();
            }});
          }}
        }})();
        </script>
        """,
        height=0,
    )


# Popup/toast high-risk alerts in dashboard tab (Docker-friendly alternative to native Windows popup).
if "last_seen_alert_ts" not in st.session_state:
    st.session_state["last_seen_alert_ts"] = None
if "last_notified_alert_key" not in st.session_state:
    st.session_state["last_notified_alert_key"] = None

if not df.empty and {"timestamp", "risk_score", "file_name", "action"}.issubset(df.columns):
    high_df = df[df["risk_score"] >= ALERT_WINDOW_MIN_SCORE].sort_values("timestamp")
    if not high_df.empty:
        latest = high_df.iloc[-1]
        latest_key = f"{latest['timestamp']}|{latest.get('file_name','')}|{latest.get('risk_score', 0)}|{latest.get('action','')}"

        # First load: still notify latest high-risk once (so user sees alert immediately).
        if st.session_state["last_seen_alert_ts"] is None:
            score = float(latest.get("risk_score", 0.0))
            name = str(latest.get("file_name", "Unknown"))
            action = str(latest.get("action", "alerted")).upper()
            msg = f"{action} | {name} | Score {score:.1f}/10"
            st.toast(f"[ALERT] {msg}", icon="[ALERT]")
            notify_browser("HybridDLP Alert", msg)
            st.session_state["last_notified_alert_key"] = latest_key
            st.session_state["last_seen_alert_ts"] = latest["timestamp"]
        else:
            new_alerts = high_df[high_df["timestamp"] > st.session_state["last_seen_alert_ts"]]
            if not new_alerts.empty:
                for _, row in new_alerts.tail(3).iterrows():
                    row_key = f"{row['timestamp']}|{row.get('file_name','')}|{row.get('risk_score', 0)}|{row.get('action','')}"
                    if row_key == st.session_state["last_notified_alert_key"]:
                        continue
                    score = float(row.get("risk_score", 0.0))
                    name = str(row.get("file_name", "Unknown"))
                    action = str(row.get("action", "alerted")).upper()
                    msg = f"{action} | {name} | Score {score:.1f}/10"
                    st.toast(f"[ALERT] {msg}", icon="[ALERT]")
                    notify_browser("HybridDLP Alert", msg)
                    st.session_state["last_notified_alert_key"] = row_key
                st.session_state["last_seen_alert_ts"] = new_alerts["timestamp"].max()

# ================= SIDEBAR =================
st.sidebar.header(" Bộ lọc")

risk_range = st.sidebar.slider("Risk Score", 0.0, 10.0, (0.0, 10.0))

action_filter = st.sidebar.multiselect(
    "Action",
    options=["allowed", "alerted", "blocked"],
    default=["allowed", "alerted", "blocked"]
)

# ================= PROCESS =================
if not df.empty:
    df["severity"] = df["risk_score"].apply(classify_severity)

    df = df[
        df["risk_score"].between(*risk_range) &
        df["action"].isin(action_filter)
    ]

# ================= NO DATA =================
if df.empty:
    st.info(
        "ℹ Chưa có dữ liệu hiển thị. "
        "Nếu vừa khởi động hệ thống, hãy tạo event thử rồi chờ dashboard tự refresh."
    )
    st.stop()

# ================= KPI =================
col1, col2, col3, col4 = st.columns(4)

col1.metric("[DATA] TỔNG SỰ KIỆN", len(df))
col2.metric("[OK] LOW", len(df[df["severity"] == "Low"]))
col3.metric("[!] HIGH+", len(df[df["severity"].isin(["High", "Critical"])]))
col4.metric(" UPDATE", datetime.now().strftime("%H:%M:%S"))

st.divider()

# ================= CHART =================
chart1, chart2, chart3 = st.columns(3)

# ---- TREND ----
with chart1:
    st.subheader(" Trend")

    df_chart = df.copy()
    # Ensure timestamp is datetime before using .dt accessor
    if pd.api.types.is_datetime64_any_dtype(df_chart["timestamp"]):
        df_chart["time_group"] = df_chart["timestamp"].dt.floor("min")
        trend_df = df_chart.groupby("time_group").size().reset_index(name="event_count")
        
        chart = alt.Chart(trend_df).mark_area().encode(
            x="time_group:T",
            y="event_count:Q",
            tooltip=["time_group:T", "event_count:Q"]
        )
        st.altair_chart(chart, width='stretch')
    else:
        st.warning("Timestamp column is not datetime type")

# ---- RISK PIE ----
with chart2:
    st.subheader(" Risk Ratio")

    risk_data = df["severity"].value_counts().reset_index()
    risk_data.columns = ["Severity", "Count"]

    pie = alt.Chart(risk_data).mark_arc(innerRadius=50).encode(
        theta="Count",
        color="Severity",
        tooltip=["Severity", "Count"]
    )

    st.altair_chart(pie, width='stretch')

# ---- KEYWORD ----
with chart3:
    st.subheader(" Top Keywords")

    if "keywords" in df.columns:
        kw = df["keywords"].explode().value_counts().head(5).reset_index()
        kw.columns = ["Keyword", "Count"]

        bar = alt.Chart(kw).mark_bar().encode(
            x="Count",
            y=alt.Y("Keyword", sort="-x")
        )

        st.altair_chart(bar, use_container_width=True)

st.divider()

# ================= TABLE =================
st.subheader("[ALERT] Alerts Log")

st.dataframe(df, width='stretch')

# ================= DEBUG =================
with st.expander("⚙ Debug"):
    st.write("Log path:", LOG_FILE)
    st.write("Total rows loaded:", len(load_data()))
    st.write("Rows after filter:", len(df))
    st.write("Action filter:", action_filter)
    st.write("Risk range:", risk_range)
    if not df.empty:
        st.write("Actions in data:", df["action"].unique().tolist())
        st.write("Risk scores in data:", df["risk_score"].min(), "-", df["risk_score"].max())
