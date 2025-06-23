import os
import threading
from datetime import datetime

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QListWidget, QListWidgetItem,
                             QComboBox, QProgressBar, QMessageBox, QFileDialog)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QIcon

from saferun.config import settings
from saferun.core.sandbox import Sandbox
from saferun.utils.file_analyzer import FileAnalyzer


class FileItemWidget(QWidget):
    """Custom widget for file list items"""

    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # File icon (simple implementation - would use file type icons in production)
        icon_label = QLabel()
        file_ext = os.path.splitext(file_path)[1].lower()
        icon_name = "file-icon.png"
        if file_ext in ['.exe', '.msi']:
            icon_name = "executable-icon.png"
        elif file_ext in ['.pdf', '.doc', '.docx']:
            icon_name = "document-icon.png"
        elif file_ext in ['.py', '.js', '.sh']:
            icon_name = "script-icon.png"

        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "resources", "icons", icon_name)
        if os.path.exists(icon_path):
            icon_label.setPixmap(QIcon(icon_path).pixmap(QSize(24, 24)))
        layout.addWidget(icon_label)

        # File info
        file_info = QVBoxLayout()
        file_name_label = QLabel(f"<b>{self.file_name}</b>")
        file_path_label = QLabel(file_path)
        file_path_label.setStyleSheet("color: gray; font-size: 9pt;")

        file_info.addWidget(file_name_label)
        file_info.addWidget(file_path_label)
        layout.addLayout(file_info, 1)

        # Status indicator
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        # Analyze button
        self.analyze_button = QPushButton("Analyze")
        layout.addWidget(self.analyze_button)

        self.setLayout(layout)

    def set_status(self, status):
        self.status_label.setText(status)
        color_map = {
            "Safe": "green",
            "Malicious": "red",
            "Suspicious": "orange",
            "Scanning...": "blue"
        }
        self.status_label.setStyleSheet(f"color: {color_map.get(status, 'black')}; font-weight: bold;")


class FilePanel(QWidget):
    scan_complete_signal = pyqtSignal(str, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.file_analyzer = FileAnalyzer()
        self.init_ui()

        # Connect signals
        self.scan_complete_signal.connect(self.on_scan_complete)

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Top controls
        top_controls = QHBoxLayout()

        # Security level selector
        top_controls.addWidget(QLabel("Security Level:"))
        self.security_level = QComboBox()
        self.security_level.addItems(["Low", "Medium", "High"])

        # Set default security level from config
        config = settings.load_config()
        default_level = config.get("sandbox", {}).get("default_security_level", "Medium").capitalize()
        index = self.security_level.findText(default_level)
        if index >= 0:
            self.security_level.setCurrentIndex(index)

        top_controls.addWidget(self.security_level)

        # Isolation method selector
        top_controls.addWidget(QLabel("Isolation Method:"))
        self.isolation_method = QComboBox()
        self.isolation_method.addItems(["Container", "Process"])

        # Set default isolation method from config
        default_method = config.get("sandbox", {}).get("isolation_method", "Container").capitalize()
        index = self.isolation_method.findText(default_method)
        if index >= 0:
            self.isolation_method.setCurrentIndex(index)

        top_controls.addWidget(self.isolation_method)

        # Add file button
        top_controls.addStretch(1)
        add_file_button = QPushButton("Add File")
        add_file_button.clicked.connect(self.browse_file)
        top_controls.addWidget(add_file_button)

        layout.addLayout(top_controls)

        # File list
        self.file_list = QListWidget()
        self.file_list.setMinimumHeight(200)
        layout.addWidget(QLabel("<b>Files to Analyze:</b>"))
        layout.addWidget(self.file_list)

        # Progress section
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Overall Progress:"))
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar, 1)

        layout.addLayout(progress_layout)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch(1)

        self.scan_all_button = QPushButton("Scan All Files")
        self.scan_all_button.clicked.connect(self.scan_all_files)
        button_layout.addWidget(self.scan_all_button)

        self.clear_button = QPushButton("Clear List")
        self.clear_button.clicked.connect(self.clear_file_list)
        button_layout.addWidget(self.clear_button)

        layout.addLayout(button_layout)

        # Status text
        self.status_label = QLabel("Add files to analyze")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze")
        if file_path:
            self.add_file(file_path)

    def add_file(self, file_path):
        file_item = QListWidgetItem()
        widget = FileItemWidget(file_path)
        file_item.setSizeHint(widget.sizeHint())
        self.file_list.addItem(file_item)
        self.file_list.setItemWidget(file_item, widget)

    def clear_file_list(self):
        self.file_list.clear()

    def scan_all_files(self):
        total = self.file_list.count()
        if total == 0:
            QMessageBox.warning(self, "No Files", "No files to scan.")
            return

        self.progress_bar.setValue(0)
        self.status_label.setText("Scanning in progress...")
        scanned = 0

        for index in range(total):
            item = self.file_list.item(index)
            widget = self.file_list.itemWidget(item)
            if not widget:
                continue

            widget.set_status("Scanning...")

            thread = threading.Thread(target=self._scan_file, args=(widget, index, total))
            thread.start()

    def _scan_file(self, widget, index, total):
        try:
            sandbox = Sandbox(
                security_level=self.security_level.currentText().lower(),
                isolation_method=self.isolation_method.currentText().lower()
            )
            report = sandbox.execute_file(widget.file_path)
            score = report.get("threat_level", 0)
            status = "Safe"
            if score >= 0.7:
                status = "Malicious"
            elif score >= 0.3:
                status = "Suspicious"
        except Exception as e:
            status = f"Error: {e}"
        finally:
            self.scan_complete_signal.emit(widget.file_path, {"status": status})
            progress = int((index + 1) / total * 100)
            self.progress_bar.setValue(progress)
            if progress == 100:
                self.status_label.setText("Scan completed successfully.")

    def on_scan_complete(self, file_path, result):
        for index in range(self.file_list.count()):
            item = self.file_list.item(index)
            widget = self.file_list.itemWidget(item)
            if widget and widget.file_path == file_path:
                widget.set_status(result.get("status", "Unknown"))
                break
