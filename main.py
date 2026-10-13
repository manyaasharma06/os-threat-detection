"""Run the three monitors and send normalized events to Person 4's engine."""
import argparse
import logging

from core.engine import ThreatEngine
from monitoring.coordinator import CoordinatorConfig, MonitoringCoordinator


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the integrated monitoring layer")
    parser.add_argument("--watch-path", required=True,
                        help="Dedicated directory to monitor for file activity")
    parser.add_argument("--db", default="threats.db", help="SQLite database path")
    parser.add_argument("--process-interval", type=float, default=2.0)
    parser.add_argument("--resource-interval", type=float, default=1.0)
    parser.add_argument("--sustained-samples", type=int, default=3)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(threadName)s %(message)s")
    engine = ThreatEngine(args.db)
    coordinator = MonitoringCoordinator(
        engine.submit,
        filesystem_path=args.watch_path,
        config=CoordinatorConfig(
            process_poll_interval_seconds=args.process_interval,
            resource_interval_seconds=args.resource_interval,
            resource_sustained_samples=args.sustained_samples,
        ),
    )
    try:
        print("Integrated monitoring running. Press Ctrl+C to stop.", flush=True)
        coordinator.run_forever()
    finally:
        coordinator.stop()
        engine.db.close()


if __name__ == "__main__":
    main()
