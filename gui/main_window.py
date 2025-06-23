import os
import sys
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTabWidget,
    QFileDialog, QMessageBox, QListWidget, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from saferun.config import settings
from saferun.core.sandbox import Sandbox
from saferun.utils.logger import LogManager
from saferun.gui.report_panel import ReportPanel
# Removed: from saferun.gui.monitor_panel import MonitorPanel
# Removed: from saferun.core.monitor import ProcessMonitor


class ScanWorker(QThread):
    """Worker thread to perform scanning in the background"""
    scan_progress = pyqtSignal(int)
    scan_complete = pyqtSignal(dict)
    scan_error = pyqtSignal(str)

    def __init__(self, file_paths, isolation_method, security_level):
        super().__init__()
        self.file_paths = file_paths
        self.isolation_method = isolation_method
        self.security_level = security_level
        self.logger = LogManager().get_logger("scan_worker")

    def run(self):
        try:
            self.logger.info(f"Starting scan for {len(self.file_paths)} files")
            sandbox = Sandbox(
                isolation_method=self.isolation_method,
                security_level=self.security_level
            )
            results = {}
            total_files = len(self.file_paths)
            for i, file_path in enumerate(self.file_paths):
                self.scan_progress.emit(int((i / total_files) * 100))
                self.logger.info(f"Scanning file: {file_path}")
                report = sandbox.execute_file(file_path)
                results[file_path] = report
                sandbox.cleanup()
            self.scan_progress.emit(100)
            self.scan_complete.emit(results)
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
            self.scan_error.emit(str(e))


class MainWindow(QMainWindow):
    """Main window for the SafeRun application"""

    def __init__(self):
        super().__init__()
        self.logger = LogManager().get_logger("gui")
        self.setWindowTitle("SafeRun - Sandbox Security System")
        self.resize(1200, 800)

        self.files_to_scan = []
        self.scan_results = {}
        self.current_worker = None

        self.setup_ui()
        self.logger.info("GUI initialized")

    def setup_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)

        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("SafeRun Security Sandbox")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        # REMOVED: Scan File button
        # scan_button = QPushButton("Scan File")
        # scan_button.clicked.connect(self.scan_files)
        # header_layout.addWidget(scan_button)
        main_layout.addLayout(header_layout)

        # Security settings
        options_layout = QHBoxLayout()
        self.security_combo = QComboBox()
        self.security_combo.addItems(["Low", "Medium", "High"])
        self.security_combo.setCurrentText("Medium")
        self.isolation_combo = QComboBox()
        self.isolation_combo.addItems(["Container", "Process"])
        options_layout.addWidget(QLabel("Security Level:"))
        options_layout.addWidget(self.security_combo)
        options_layout.addWidget(QLabel("Isolation Method:"))
        options_layout.addWidget(self.isolation_combo)
        options_layout.addStretch()
        add_file_button = QPushButton("Add File")
        add_file_button.clicked.connect(self.add_files)
        options_layout.addWidget(add_file_button)
        main_layout.addLayout(options_layout)

        # File list
        file_section_layout = QVBoxLayout()
        file_section_layout.addWidget(QLabel("Files to Analyze:"))
        self.file_list = QListWidget()
        file_section_layout.addWidget(self.file_list)
        file_buttons_layout = QHBoxLayout()
        clear_button = QPushButton("Clear List")
        clear_button.clicked.connect(self.clear_file_list)
        scan_all_button = QPushButton("Scan All Files")
        scan_all_button.clicked.connect(self.scan_files)
        file_buttons_layout.addStretch()
        file_buttons_layout.addWidget(clear_button)
        file_buttons_layout.addWidget(scan_all_button)
        file_section_layout.addLayout(file_buttons_layout)
        main_layout.addLayout(file_section_layout)

        # Progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Overall Progress:"))
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        main_layout.addLayout(progress_layout)

        # Result tabs
        self.result_tabs = QTabWidget()
        self.scan_results_widget = QWidget()
        self.scan_results_layout = QVBoxLayout(self.scan_results_widget)
        self.result_tabs.addTab(self.scan_results_widget, "Scan Results")

        # REMOVED: Process Monitor tab
        # self.monitoring_widget = QWidget()
        # self.monitoring_layout = QVBoxLayout(self.monitoring_widget)
        # self.result_tabs.addTab(self.monitoring_widget, "Process Monitor")

        self.report_widget = QWidget()
        self.report_layout = QVBoxLayout(self.report_widget)
        self.result_tabs.addTab(self.report_widget, "Analysis Reports")
        main_layout.addWidget(self.result_tabs)

        self.setCentralWidget(central_widget)
        self.statusBar().showMessage("Ready")

    def add_files(self):
        file_dialog = QFileDialog()
        files, _ = file_dialog.getOpenFileNames(
            self, "Select Files to Scan", "", "All Files (*.*)"
        )
        if files:
            for file_path in files:
                if file_path not in self.files_to_scan:
                    self.files_to_scan.append(file_path)
                    self.file_list.addItem(file_path)
            self.statusBar().showMessage(f"{len(files)} file(s) added to scan list")
            self.logger.info(f"Added {len(files)} files to scan list")

    def clear_file_list(self):
        self.files_to_scan = []
        self.file_list.clear()
        self.statusBar().showMessage("File list cleared")
        self.logger.info("File list cleared")

    def scan_files(self):
        if not self.files_to_scan:
            QMessageBox.warning(self, "No Files", "Please add files to scan first.")
            return

        isolation_method = self.isolation_combo.currentText().lower()
        security_level = self.security_combo.currentText().lower()
        self.clear_results()

        self.current_worker = ScanWorker(
            self.files_to_scan, isolation_method, security_level
        )
        self.current_worker.scan_progress.connect(self.update_progress)
        self.current_worker.scan_complete.connect(self.handle_scan_complete)
        self.current_worker.scan_error.connect(self.handle_scan_error)

        self.progress_bar.setValue(0)
        self.statusBar().showMessage("Scanning in progress...")
        self.current_worker.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def handle_scan_complete(self, results):
        self.scan_results = results
        self.display_results()
        self.statusBar().showMessage("Scan completed")
        self.logger.info("Scan completed successfully")

    def handle_scan_error(self, error_message):
        QMessageBox.critical(self, "Scan Error", f"Error during scan: {error_message}")
        self.statusBar().showMessage("Scan failed")
        self.logger.error(f"Scan failed: {error_message}")

    def clear_results(self):
        for layout in [self.scan_results_layout, self.report_layout]:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()

    def display_results(self):
        if not self.scan_results:
            return
        for file_path, report in self.scan_results.items():
            file_name = os.path.basename(file_path)
            self.scan_results_layout.addWidget(QLabel(f"<b>File: {file_name}</b>"))
            self.scan_results_layout.addWidget(QLabel(f"Status: {report.get('status', 'Unknown')}"))

            exec_time = report.get("execution_time", 0)
            self.scan_results_layout.addWidget(QLabel(f"Execution Time: {exec_time:.2f} seconds"))

            score = report.get("threat_level", 0.0)
            score_color = "green" if score <= 0.3 else "orange" if score <= 0.6 else "red"
            score_label = QLabel(f"Threat Score: <span style='color:{score_color};'>{score:.2f}</span>")
            self.scan_results_layout.addWidget(score_label)

            if score >= 0.6:
                alert_msg = f"⚠️ The file '{file_name}' is MALICIOUS!\nThreat Score: {score:.2f}"
                QMessageBox.critical(self, "Malicious File Detected", alert_msg)
                malicious_label = QLabel("<b><span style='color:red;'>This file is malicious.</span></b>")
                self.scan_results_layout.addWidget(malicious_label)

            threats = report.get("threat_analysis", {}).get("threats", [])
            if threats:
                self.scan_results_layout.addWidget(QLabel("<b>Detected Threats:</b>"))
                for t in threats:
                    sig = t.get("signature_name", t.get("type", "Unknown"))
                    lvl = t.get("threat_level", "Unknown")
                    desc = t.get("details", "")
                    self.scan_results_layout.addWidget(QLabel(f"- {sig} ({lvl}): {desc}"))

            separator = QLabel("")
            separator.setStyleSheet("min-height: 1px; background-color: #ccc;")
            self.scan_results_layout.addWidget(separator)

            # ✅ SHOW ANALYSIS REPORT PANEL
            report_panel = ReportPanel()
            report_panel.display_report(report)
            self.report_layout.addWidget(report_panel)

            # REMOVED: Monitoring Panel logic

            # ✅ PRINT THE WHOLE REPORT
            print(f"[Complete Report for {file_name}]:")
            import json
            print(json.dumps(report, indent=2))

        self.scan_results_layout.addStretch()
