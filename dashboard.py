
import sqlite3
from pathlib import Path
import html

import pandas as pd
import streamlit as st


# =====================================================
# 1. CONFIGURATION
# =====================================================

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = PROJECT_DIR / "threats.db"

BG = "#F4F7F5"
PANEL = "#FFFFFF"
TEXT = "#253238"
MUTED = "#62736F"
ACCENT = "#658E9C"
BORDER = "#DCE5E0"

SEVERITY_COLORS = {
    "LOW": "#D6F9DD",
    "MEDIUM": "#F7B23B",
    "HIGH": "#B7A5E5",
    "CRITICAL": "#E85F5C",
}

st.set_page_config(
    page_title="ThreatWatch | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =====================================================
# 2. CUSTOM CSS — ALL STYLING GOES INSIDE THIS BLOCK
# =====================================================

st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: {BG};
        color: {TEXT};
    }}

    [data-testid="stHeader"] {{
        background-color: {BG};
    }}

    [data-testid="stSidebar"] {{
        background-color: #EAF0EC;
        border-right: 1px solid {BORDER};
    }}

    /* General headings and text */
    h1, h2, h3, h4, p, label {{
        color: {TEXT};
    }}

    /* FIX: sidebar heading colour */
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] h4 {{
        color: {TEXT} !important;
    }}

    /* FIX: sidebar descriptions and Markdown text */
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] span {{
        color: {TEXT} !important;
    }}

    /* Sidebar labels */
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] label p {{
        color: {TEXT} !important;
    }}

    /* Metric cards */
    [data-testid="stMetric"] {{
        background: {PANEL};
        border: 1px solid {BORDER};
        border-radius: 13px;
        padding: 17px;
        box-shadow: 0 2px 7px rgba(37, 50, 56, 0.04);
    }}

    [data-testid="stMetricLabel"] {{
        color: {MUTED} !important;
    }}

    [data-testid="stMetricValue"] {{
        color: {TEXT} !important;
        font-weight: 750;
    }}

    /* Tables */
    div[data-testid="stDataFrame"] {{
        border: 1px solid {BORDER};
        border-radius: 10px;
        overflow: hidden;
    }}

    /* Buttons */
    div.stButton > button,
    div.stDownloadButton > button {{
        background-color: {ACCENT};
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        min-height: 40px;
    }}

    div.stButton > button:hover,
    div.stDownloadButton > button:hover {{
        background-color: #4E7785;
        color: white;
    }}

    /* Input fields */
    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {{
        background-color: white;
        border-color: {BORDER};
    }}

    /* Header banner */
    .hero {{
        background: linear-gradient(120deg, #FFFFFF, #EAF3EE);
        border: 1px solid {BORDER};
        border-left: 6px solid {ACCENT};
        border-radius: 15px;
        padding: 23px 26px;
        margin-bottom: 20px;
    }}

    .hero-title {{
        color: {TEXT};
        font-size: 30px;
        font-weight: 800;
    }}

    .hero-subtitle {{
        color: {MUTED};
        font-size: 14px;
        margin-top: 6px;
    }}

    .section-title {{
        font-size: 21px;
        font-weight: 750;
        color: {TEXT};
        margin: 12px 0;
    }}

    .alert-card {{
        background: white;
        border: 1px solid {BORDER};
        border-left: 5px solid {ACCENT};
        border-radius: 10px;
        padding: 15px;
        margin-bottom: 10px;
    }}

    .pill {{
        display: inline-block;
        padding: 5px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 800;
        margin-bottom: 7px;
    }}

    .muted {{
        color: {MUTED};
        font-size: 13px;
    }}

    hr {{
        border-color: {BORDER};
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# =====================================================
# 3. DATABASE FUNCTIONS
# =====================================================

@st.cache_data(ttl=3)
def load_data():
    """Load event and alert records from SQLite."""

    if not DB_PATH.exists():
        return pd.DataFrame(), pd.DataFrame()

    connection = sqlite3.connect(DB_PATH, timeout=10)

    try:
        events = pd.read_sql_query(
            """
            SELECT id, timestamp, source, event_type, description,
                   pid, process_name, value, details
            FROM events
            ORDER BY id DESC
            """,
            connection,
        )

        alerts = pd.read_sql_query(
            """
            SELECT id, timestamp, score, severity, reason, event_id
            FROM alerts
            ORDER BY id DESC
            """,
            connection,
        )
    finally:
        connection.close()

    return events, alerts


def add_datetime(df):
    """Convert database timestamps to readable datetime values."""

    df = df.copy()

    if "timestamp" not in df.columns:
        df["datetime"] = pd.NaT
        return df

    if pd.api.types.is_numeric_dtype(df["timestamp"]):
        df["datetime"] = pd.to_datetime(
            df["timestamp"], unit="s", errors="coerce"
        )
    else:
        parsed = pd.to_datetime(
            df["timestamp"], errors="coerce", utc=True
        )
        df["datetime"] = parsed.dt.tz_convert(None)

    return df


def reset_filters():
    """Reset filter widgets to their default selections."""

    for key in (
        "source_filter",
        "severity_filter",
        "type_filter",
        "search_filter",
        "date_filter",
    ):
        st.session_state.pop(key, None)


def csv_bytes(df):
    return df.to_csv(index=False).encode("utf-8")


events, alerts = load_data()
events = add_datetime(events)
alerts = add_datetime(alerts)

if not alerts.empty:
    alerts["severity"] = (
        alerts["severity"].fillna("UNKNOWN").astype(str).str.upper()
    )


# =====================================================
# 4. HEADER
# =====================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-title">🛡️ ThreatWatch</div>
        <div class="hero-subtitle">
            OS-LEVEL SECURITY AND THREAT DETECTION
            <br>
            Monitor activity · Understand alerts · Explore system behaviour
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# =====================================================
# 5. SIDEBAR AND WORKING FILTERS
# =====================================================

st.sidebar.title("Dashboard Controls")
st.sidebar.caption("Use these controls to explore your data.")

button_col1, button_col2 = st.sidebar.columns(2)

with button_col1:
    if st.button("🔄 Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

with button_col2:
    st.button(
        "↩ Reset",
        use_container_width=True,
        on_click=reset_filters,
    )

st.sidebar.divider()

source_options = (
    sorted(events["source"].dropna().astype(str).unique().tolist())
    if not events.empty else []
)

type_options = (
    sorted(events["event_type"].dropna().astype(str).unique().tolist())
    if not events.empty else []
)

selected_sources = st.sidebar.multiselect(
    "Monitoring source",
    options=source_options,
    default=source_options,
    key="source_filter",
)

selected_types = st.sidebar.multiselect(
    "Event type",
    options=type_options,
    default=type_options,
    key="type_filter",
)

selected_severities = st.sidebar.multiselect(
    "Alert severity",
    options=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    default=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    key="severity_filter",
)

search_text = st.sidebar.text_input(
    "Search events",
    placeholder="e.g. file, CPU, process...",
    key="search_filter",
)

valid_dates = (
    events["datetime"].dropna()
    if not events.empty else pd.Series(dtype="datetime64[ns]")
)

if not valid_dates.empty:
    earliest_date = valid_dates.min().date()
    latest_date = valid_dates.max().date()

    selected_dates = st.sidebar.date_input(
        "Event date range",
        value=(earliest_date, latest_date),
        min_value=earliest_date,
        max_value=max(latest_date, earliest_date),
        key="date_filter",
    )
else:
    selected_dates = None
    st.sidebar.caption("Date filter appears when timestamped events exist.")

st.sidebar.divider()
st.sidebar.markdown("### Severity Guide")

for name, color in SEVERITY_COLORS.items():
    st.sidebar.markdown(
        f"""
        <div style="display:flex;align-items:center;gap:9px;margin:9px 0;">
            <span style="width:13px;height:13px;border-radius:4px;
                         background:{color};display:inline-block;"></span>
            <span style="color:{TEXT};font-weight:600;">{name}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =====================================================
# 6. APPLY FILTERS
# =====================================================

filtered_events = events.copy()

if not filtered_events.empty:
    filtered_events = filtered_events[
        filtered_events["source"].fillna("").astype(str).isin(selected_sources)
    ]

    filtered_events = filtered_events[
        filtered_events["event_type"].fillna("").astype(str).isin(selected_types)
    ]

    if search_text.strip():
        searchable_columns = [
            c for c in [
                "source", "event_type", "description", "process_name"
            ]
            if c in filtered_events.columns
        ]

        search_mask = pd.Series(False, index=filtered_events.index)

        for column in searchable_columns:
            search_mask |= (
                filtered_events[column]
                .fillna("")
                .astype(str)
                .str.contains(search_text.strip(), case=False, regex=False)
            )

        filtered_events = filtered_events[search_mask]

    if (
        selected_dates is not None
        and isinstance(selected_dates, (tuple, list))
        and len(selected_dates) == 2
    ):
        start_date, end_date = selected_dates

        if start_date and end_date:
            event_days = filtered_events["datetime"].dt.date
            filtered_events = filtered_events[
                event_days.between(start_date, end_date)
            ]

filtered_alerts = alerts.copy()

if not filtered_alerts.empty:
    filtered_alerts = filtered_alerts[
        filtered_alerts["severity"].isin(selected_severities)
    ]

    if (
        selected_dates is not None
        and isinstance(selected_dates, (tuple, list))
        and len(selected_dates) == 2
    ):
        start_date, end_date = selected_dates

        if start_date and end_date:
            alert_days = filtered_alerts["datetime"].dt.date
            filtered_alerts = filtered_alerts[
                alert_days.between(start_date, end_date)
            ]


# =====================================================
# 7. SUMMARY METRICS
# =====================================================

st.markdown(
    '<div class="section-title">📊 Security Overview</div>',
    unsafe_allow_html=True,
)

total_events = len(filtered_events)
total_alerts = len(filtered_alerts)

high_critical = (
    int(filtered_alerts["severity"].isin(["HIGH", "CRITICAL"]).sum())
    if not filtered_alerts.empty else 0
)

critical_total = (
    int((filtered_alerts["severity"] == "CRITICAL").sum())
    if not filtered_alerts.empty else 0
)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events Found", f"{total_events:,}")
c2.metric("Alerts Found", f"{total_alerts:,}")
c3.metric("High / Critical", f"{high_critical:,}")
c4.metric("Critical Alerts", f"{critical_total:,}")

st.caption("Metrics reflect your current filters.")
st.divider()


# =====================================================
# 8. EVENT SOURCE AND EVENT TYPE GRAPHS
# =====================================================

st.markdown(
    '<div class="section-title">📈 Activity Analytics</div>',
    unsafe_allow_html=True,
)

left, right = st.columns(2)

with left:
    st.subheader("Events by monitoring source")

    if filtered_events.empty:
        st.info("No events match the current filters.")
    else:
        source_counts = (
            filtered_events["source"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("Source")
            .reset_index(name="Events")
        )

        st.bar_chart(source_counts, x="Source", y="Events", color=ACCENT)

with right:
    st.subheader("Most frequent event types")

    if filtered_events.empty:
        st.info("No event types to display.")
    else:
        type_counts = (
            filtered_events["event_type"]
            .fillna("UNKNOWN")
            .value_counts()
            .head(10)
            .rename_axis("Event Type")
            .reset_index(name="Count")
        )

        st.bar_chart(
            type_counts,
            x="Event Type",
            y="Count",
            color="#8CBFA8",
        )


# =====================================================
# 9. EVENT TIMELINE
# =====================================================

st.subheader("🕒 Event Activity Over Time")

if filtered_events.empty:
    st.info("No matching events are available.")
else:
    timeline = filtered_events.dropna(subset=["datetime"]).copy()

    if timeline.empty:
        st.info("The selected records have no valid timestamps.")
    else:
        timeline["Time"] = timeline["datetime"].dt.floor("min")

        timeline_data = (
            timeline.groupby("Time")
            .size()
            .reset_index(name="Events")
            .sort_values("Time")
            .set_index("Time")
        )

        st.line_chart(timeline_data, y="Events", color=ACCENT)
        st.caption("Each point represents the number of events per minute.")


# =====================================================
# 10. ALERT SEVERITY GRAPHS
# =====================================================

st.divider()

st.markdown(
    '<div class="section-title">🚦 Threat Severity Analysis</div>',
    unsafe_allow_html=True,
)

if filtered_alerts.empty:
    st.info("No alerts match the selected filters.")
else:
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    severity_counts = (
        filtered_alerts["severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
        .rename_axis("Severity")
        .reset_index(name="Alerts")
    )

    severity_left, severity_right = st.columns(2)

    with severity_left:
        st.subheader("Alert count by severity")
        st.bar_chart(
            severity_counts,
            x="Severity",
            y="Alerts",
            color=ACCENT,
        )

    with severity_right:
        st.subheader("Alert score distribution")

        score_data = filtered_alerts.copy()
        score_data["score"] = pd.to_numeric(
            score_data["score"], errors="coerce"
        )
        score_data = score_data.dropna(subset=["score"])

        if score_data.empty:
            st.info("No numeric alert scores are available.")
        else:
            score_bins = pd.cut(
                score_data["score"],
                bins=[-float("inf"), 29, 59, 89, float("inf")],
                labels=[
                    "LOW (<30)",
                    "MEDIUM (30-59)",
                    "HIGH (60-89)",
                    "CRITICAL (90+)",
                ],
            )

            score_counts = (
                score_bins.value_counts(sort=False)
                .rename_axis("Score range")
                .reset_index(name="Alerts")
            )

            st.bar_chart(
                score_counts,
                x="Score range",
                y="Alerts",
                color="#B7A5E5",
            )

    st.caption(
        "Score ranges follow the project's severity thresholds. "
        "Recorded severity is still determined by the threat engine."
    )


# =====================================================
# 11. FILE-SYSTEM ACTIVITY
# =====================================================

st.divider()

st.markdown(
    '<div class="section-title">📁 File-System Activity</div>',
    unsafe_allow_html=True,
)

if filtered_events.empty:
    st.info("No matching events are available.")
else:
    file_mask = (
        filtered_events["source"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.contains("file", regex=False)
    ) | (
        filtered_events["event_type"]
        .fillna("")
        .astype(str)
        .str.upper()
        .str.contains(
            "FILE_CREATED|FILE_MODIFIED|FILE_DELETED|FILE_RENAMED|"
            "MASS_FILE_CHANGE|RANSOMWARE_PATTERN",
            regex=True,
        )
    )

    file_events = filtered_events[file_mask].copy()

    if file_events.empty:
        st.info(
            "No file-system events match the filters. "
            "Try selecting the filesystem source in the sidebar."
        )
    else:
        file_counts = (
            file_events["event_type"]
            .fillna("UNKNOWN")
            .value_counts()
            .rename_axis("File Event")
            .reset_index(name="Count")
        )

        st.bar_chart(file_counts, x="File Event", y="Count", color="#8CBFA8")

        st.caption(f"{len(file_events):,} matching file-related events.")

        file_columns = [
            c for c in [
                "id", "datetime", "event_type", "description",
                "pid", "process_name",
            ]
            if c in file_events.columns
        ]

        st.dataframe(
            file_events[file_columns].head(50),
            use_container_width=True,
            hide_index=True,
        )


# =====================================================
# 12. RECENT EVENTS TABLE AND CSV DOWNLOAD
# =====================================================

st.divider()

st.markdown(
    '<div class="section-title">🧾 Recent Security Events</div>',
    unsafe_allow_html=True,
)

if filtered_events.empty:
    st.info("No events match the current filters.")
else:
    event_columns = [
        c for c in [
            "id", "datetime", "source", "event_type",
            "description", "pid", "process_name", "value",
        ]
        if c in filtered_events.columns
    ]

    display_events = filtered_events[event_columns].copy()

    if "datetime" in display_events.columns:
        display_events["datetime"] = display_events["datetime"].dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    display_events = display_events.rename(
        columns={
            "id": "ID",
            "datetime": "Timestamp",
            "source": "Source",
            "event_type": "Event Type",
            "description": "Description",
            "pid": "PID",
            "process_name": "Process",
            "value": "Value",
        }
    )

    st.dataframe(
        display_events.head(100),
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "⬇ Download filtered events as CSV",
        data=csv_bytes(display_events),
        file_name="threatwatch_events.csv",
        mime="text/csv",
    )

    st.caption("The table shows 100 rows at most; the CSV contains all matches.")


# =====================================================
# 13. RECENT ALERTS AND CSV DOWNLOAD
# =====================================================

st.divider()

st.markdown(
    '<div class="section-title">🚨 Recent Threat Alerts</div>',
    unsafe_allow_html=True,
)

if filtered_alerts.empty:
    st.success("No alerts match the current filters.")
else:
    for _, alert in filtered_alerts.head(10).iterrows():
        severity = str(alert.get("severity", "UNKNOWN")).upper()
        color = SEVERITY_COLORS.get(severity, ACCENT)

        reason = html.escape(str(alert.get("reason", "No reason provided")))
        score = html.escape(str(alert.get("score", "N/A")))
        event_id = html.escape(str(alert.get("event_id", "N/A")))

        timestamp = alert.get("datetime")
        timestamp_text = (
            timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if pd.notna(timestamp)
            else str(alert.get("timestamp", "Unknown"))
        )
        timestamp_text = html.escape(timestamp_text)

        st.markdown(
            f"""
            <div class="alert-card" style="border-left-color:{color};">
                <span class="pill"
                      style="background:{color};color:#253238;">
                    {html.escape(severity)}
                </span>
                <div style="font-weight:700;color:{TEXT};margin-bottom:6px;">
                    {reason}
                </div>
                <div class="muted">
                    Score: <b>{score}</b>
                    &nbsp; | &nbsp; Related event ID: {event_id}
                    <br>Timestamp: {timestamp_text}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    alert_columns = [
        c for c in [
            "id", "datetime", "score", "severity", "reason", "event_id"
        ]
        if c in filtered_alerts.columns
    ]

    display_alerts = filtered_alerts[alert_columns].copy()

    if "datetime" in display_alerts.columns:
        display_alerts["datetime"] = display_alerts["datetime"].dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    with st.expander("View all matching alerts"):
        st.dataframe(
            display_alerts,
            use_container_width=True,
            hide_index=True,
        )

    st.download_button(
        "⬇ Download filtered alerts as CSV",
        data=csv_bytes(display_alerts),
        file_name="threatwatch_alerts.csv",
        mime="text/csv",
    )


# =====================================================
# 14. FOOTER
# =====================================================

st.divider()

st.markdown(
    f"""
    <div style="text-align:center;padding:12px;color:{MUTED};">
        <b>ThreatWatch</b> · OS-Level Security and Threat Detection
        <br>
        <span style="font-size:12px;">
            Python · SQLite · Streamlit
            <br>
            Data is loaded from your local threats.db database.
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)
