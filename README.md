# OS-Level Security and Threat Detection Platform

## Overview

The **OS-Level Security and Threat Detection Platform** is a Python-based application that monitors operating-system activity, identifies potentially suspicious behaviour, and assigns threat scores to detected events.

The project integrates three monitoring modules with a central threat detection engine and a Streamlit dashboard.

## Project Objectives

- Monitor running processes and identify suspicious process behaviour.
- Track file-system activity, including file creation, modification, deletion, and renaming.
- Monitor system and process resource usage, such as CPU and memory.
- Normalize monitoring events and send them to a central threat detection engine.
- Assign threat scores and severity levels to events.
- Store detected events and alerts in an SQLite database.
- Display monitoring results through a Streamlit dashboard.

## Architecture

The application follows this workflow:

1. **Process Monitoring:** Collects process information and detects new or suspicious processes and sustained high CPU usage.
2. **File-System Monitoring:** Detects file activity and patterns that may indicate mass file changes or ransomware-like behaviour.
3. **Resource Monitoring:** Detects sustained high system or process resource usage.
4. **Event Adapters:** Convert monitoring outputs into a common event format.
5. **Monitoring Coordinator:** Starts and manages the monitoring modules and dispatches their events.
6. **Threat Detection Engine:** Evaluates events, calculates threat scores, determines severity, and generates alerts.
7. **SQLite Database:** Stores events and alerts.
8. **Streamlit Dashboard:** Displays information from the database.

## Technology Stack

- **Language:** Python
- **Process and resource monitoring:** `psutil`
- **File-system monitoring:** `watchdog`
- **Database:** SQLite
- **Dashboard:** Streamlit
- **Data handling:** pandas
- **Testing:** Python `unittest`
- **Version control:** Git and GitHub

## Project Structure

```text
os-threat-detection/
├── core/
│   ├── adapters.py
│   ├── database.py
│   ├── engine.py
│   ├── event.py
│   ├── correlator.py
│   └── scoring.py
├── filesystem_monitoring/
│   └── file_monitor.py
├── monitoring/
│   └── coordinator.py
├── resource_monitoring/
│   ├── resource_monitor.py
│   └── simulate_workload.py
├── tests/
│   ├── test_adapters.py
│   ├── test_coordinator.py
│   └── test_file_monitor.py
├── process_monitor.py
├── main.py
├── dashboard.py
├── requirements.txt
├── MONITORING_INTEGRATION.md
└── README.md
```

*Note: The tree highlights the main integration files; other project files and documentation may also be present.*

## Prerequisites

Install the following before running the project:

- Python 3.10 or a compatible version supported by the project's dependencies
- Git
- Visual Studio Code (recommended)

## Clone the Integration Branch

The integrated version is available on the `integration-engine` branch.

Open Terminal and run:

```bash
git clone -b integration-engine --single-branch https://github.com/manyaasharma06/os-threat-detection.git
cd os-threat-detection
```

These commands download the repository's integration branch and enter the project directory.

## Installation and Setup

### 1. Create a virtual environment

On macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If a dependency required by the dashboard is missing, install the missing package in the activated environment.

### 3. Prepare a dedicated monitoring directory

The application requires an existing directory to watch. Create one for testing:

```bash
mkdir -p monitor_test_files
```

Use a dedicated test directory rather than an important personal folder.

## Running the Integrated Monitoring Application

Start the monitoring coordinator and threat detection engine:

```bash
python main.py --watch-path monitor_test_files
```

The application should display a message indicating that integrated monitoring is running.

The coordinator starts the process, file-system, and resource monitoring components. Events are normalized and passed to the central engine, which stores them in the SQLite database and creates alerts when the configured threshold is reached.

Press **Ctrl+C** to stop the application.

## Testing File-System Monitoring

Keep the integrated monitoring application running. Open a second terminal in the same project directory, activate the virtual environment if needed, and run:

```bash
touch monitor_test_files/integration_test.txt
```

This creates a test file inside the monitored directory.

The event may not print an alert in the terminal because ordinary file-creation events have a low threat score. Check the database or dashboard to confirm that the event was recorded.

## Running the Dashboard

Open another terminal in the project directory and activate the virtual environment.

Run:

```bash
streamlit run dashboard.py
```

Open the local URL displayed in the terminal, usually:

`http://localhost:8501`

The dashboard provides a visual interface for inspecting the stored monitoring and threat-detection results.

## Running Automated Tests

From the project root, with the virtual environment activated, run:

```bash
python -m unittest discover -v
```

The test suite checks monitoring behaviour, event adapters, and coordinator functionality. A successful run ends with `OK`.

## Threat Scoring and Alerts

The central engine calculates a score for each event based on configured scoring rules.

The default severity levels are:

| Score | Severity |
|---:|---|
| Below 30 | Low |
| 30–59 | Medium |
| 60–89 | High |
| 90 and above | Critical |

Alerts are generated when the score reaches the configured threshold. The current default alert threshold is 30.

These scores are rule-based indicators for this project, not a guarantee that an event is malicious.

## Database

The application uses SQLite to store monitoring events and generated alerts. The default database path is:

```text
threats.db
```

The database is created locally when the application initializes. It is runtime data and should generally not be committed to GitHub.

## Git Branch Information

- **Integration branch:** `integration-engine`
- **Repository:** https://github.com/manyaasharma06/os-threat-detection
- **Purpose:** Combine the monitoring modules with the central threat detection engine and dashboard.

To download the latest integration branch in an existing clone:

```bash
git switch integration-engine
git pull origin integration-engine
```

If the branch has not been fetched yet, run:

```bash
git fetch origin
git switch --track origin/integration-engine
```

## Important Notes

- Run commands from the project root unless otherwise specified.
- Activate the virtual environment before installing dependencies or running the application.
- The monitoring directory must exist before starting `main.py`.
- The dashboard and monitoring application can run in separate terminals.
- Runtime databases, virtual environments, and temporary test files should not be committed unless the team explicitly decides otherwise.
- Run the automated tests after making integration changes.

## Contributors

This project is developed collaboratively, with separate contributions for process monitoring, file-system monitoring, resource monitoring, and the central threat detection engine and integration.

## Disclaimer

This is an academic project intended for learning and demonstration. Threat scores and alerts are based on implemented detection rules and should not be treated as a complete production-grade security solution.
