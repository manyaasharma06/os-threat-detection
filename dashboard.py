import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st


PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = PROJECT_DIR / "threats.db"

st.set_page_config(
    page_title="OS Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ OS Threat Detection Dashboard")
st.caption("Behavioural analysis and threat monitoring")
st.divider()


@st.cache_data(ttl=3)
def load_data():
    """Read the current events and alerts from SQLite."""
    if not DB_PATH.exists():
        return pd.DataFrame(), pd.DataFrame()

    connection = sqlite3.connect(DB_PATH)

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


events, alerts = load_data()

# Sidebar controls
st.sidebar.header("Dashboard controls")

if st.sidebar.button("🔄 Refresh data"):
    st.cache_data.clear()
    st.rerun()

if not events.empty:
    sources = sorted(events["source"].dropna().unique().tolist())
    selected_sources = st.sidebar.multiselect(
        "Filter by event source",
        options=sources,
        default=sources,
    )

    filtered_events = events[
        events["source"].isin(selected_sources)
    ]
else:
    filtered_events = events

# Summary metrics
total_events = len(events)
total_alerts = len(alerts)

if not events.empty and "severity" in events.columns:
    pass

critical_alerts = (
    int((alerts["severity"] == "CRITICAL").sum())
    if not alerts.empty else 0
)
high_alerts = (
    int((alerts["severity"] == "HIGH").sum())
    if not alerts.empty else 0
)
medium_alerts = (
    int((alerts["severity"] == "MEDIUM").sum())
    if not alerts.empty else 0
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", f"{total_events:,}")
col2.metric("Total Alerts", f"{total_alerts:,}")
col3.metric("High / Critical Alerts", high_alerts + critical_alerts)
col4.metric("Medium Alerts", medium_alerts)

st.divider()

# Event source summary
st.subheader("📊 Events by Monitoring Source")

if filtered_events.empty:
    st.info("No events found for the selected filters.")
else:
    source_counts = (
        filtered_events["source"]
        .fillna("Unknown")
        .value_counts()
        .rename_axis("Source")
        .reset_index(name="Events")
    )

    chart_col, table_col = st.columns([3, 2])

    with chart_col:
        st.bar_chart(source_counts, x="Source", y="Events")

    with table_col:
        st.dataframe(source_counts, use_container_width=True, hide_index=True)

# Event type distribution
st.subheader("🔎 Event Type Distribution")

if not filtered_events.empty:
    event_counts = (
        filtered_events["event_type"]
        .fillna("UNKNOWN")
        .value_counts()
        .rename_axis("Event Type")
        .reset_index(name="Count")
    )

    st.bar_chart(event_counts, x="Event Type", y="Count")

# Recent events
st.subheader("🧾 Recent Events")

if filtered_events.empty:
    st.info("No events to display.")
else:
    display_columns = [
        column for column in [
            "id", "timestamp", "source", "event_type",
            "description", "pid", "process_name", "value",
        ]
        if column in filtered_events.columns
    ]

    st.dataframe(
        filtered_events[display_columns].head(100),
        use_container_width=True,
        hide_index=True,
    )

# Alerts
st.subheader("🚨 Threat Alerts")

if alerts.empty:
    st.success("No alerts have been recorded yet.")
else:
    st.dataframe(
        alerts[
            ["id", "timestamp", "score", "severity", "reason", "event_id"]
        ].head(100),
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "Data source: local SQLite database. "
    "Use Refresh data to reload the latest records."
)
