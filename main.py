import os
import sys
import argparse
import json  # ✅ ADDED
from pathlib import Path
from saferun.config import settings
from saferun.core.sandbox import Sandbox
from saferun.utils.logger import LogManager
from saferun.core.threat_detector import ThreatLevel  # Required for .name in CLI


def init_app():
    settings.init_directories()
    config = settings.load_config()
    return config


def run_sandbox(file_path: str, security_level: str = "medium", isolation_method: str = "container") -> dict:
    logger = LogManager().get_logger("main")
    logger.info(f"Starting sandbox execution for {file_path}")
    sandbox = Sandbox(isolation_method=isolation_method, security_level=security_level)
    report = sandbox.execute_file(file_path)
    logger.info(f"Execution completed with status: {report.get('status', 'unknown')}")
    return report


def launch_gui() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
        from saferun.gui.main_window import MainWindow

        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        return app.exec()
    except ImportError:
        print("Error: GUI components not found. Make sure PyQt6 is installed and saferun.gui module exists.")
        print("You can install PyQt6 with: pip install PyQt6")
        return 1
    except Exception as e:
        print(f"Unexpected error while launching GUI: {e}")
        return 1


def main() -> int:
    config = init_app()

    parser = argparse.ArgumentParser(description="SafeRun - Cross-Platform Local Sandbox Security System")
    parser.add_argument("file", nargs="?", help="File to execute in sandbox")
    parser.add_argument("--security", choices=["low", "medium", "high"],
                        default=config["sandbox"]["default_security_level"],
                        help="Security level")
    parser.add_argument("--isolation", choices=["container", "process"],
                        default=config["sandbox"]["isolation_method"],
                        help="Isolation method")
    parser.add_argument("--gui", action="store_true", help="Force GUI mode")
    parser.add_argument("--cli", action="store_true", help="Force CLI mode even if no file is provided")

    args = parser.parse_args()

    if (not args.file or args.gui) and not args.cli:
        return launch_gui()

    if args.cli and not args.file:
        parser.print_help()
        return 0

    file_path = os.path.abspath(args.file)
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return 1

    try:
        report = run_sandbox(file_path, args.security, args.isolation)

        print("\n🧾 Execution Report:")
        print(f"File: {report.get('file')}")
        print(f"Status: {report.get('status')}")
        print(f"Execution Time: {report.get('execution_time', 0):.2f} seconds")

        score = report.get('threat_level', 0.0)
        status_label = "Safe" if score <= 0.3 else "Suspicious" if score <= 0.6 else "Malicious"
        print(f"Threat Score: {score:.2f} ({status_label})")

        if report.get('threat_analysis'):
            threat_count = report['threat_analysis'].get('threat_count', 0)
            highest_level = report['threat_analysis'].get('highest_threat_level', ThreatLevel.NONE).name

            print(f"\nThreat Analysis:")
            print(f"Total Threats Detected: {threat_count}")
            print(f"Highest Threat Level: {highest_level}")

            threats = report['threat_analysis'].get('threats', [])
            if threats:
                print("\nDetected Threats:")
                for threat in threats:
                    print(f"- {threat.get('signature_name', threat.get('type'))} ({threat.get('threat_level', 'N/A')})")

        # ✅ ADDED: Print monitoring sections like in GUI
        print("\n🔍 Process Monitor Output:")
        for section in ["file_operations", "network_activity", "registry_operations"]:
            if section in report:
                print(f"\n[{section.replace('_', ' ').title()}]")
                for item in report[section]:
                    print(json.dumps(item, indent=2))

        # ✅ ADDED: Print full raw report like Analysis Report tab
        print("\n🧾 Full Report JSON:")
        print(json.dumps(report, indent=2))

        return 0

    except Exception as e:
        print(f"Error running sandbox: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
