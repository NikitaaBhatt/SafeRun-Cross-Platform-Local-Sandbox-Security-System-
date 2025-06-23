import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtGui import QFont


class ReportPanel(QWidget):
    """
    Minimal Analysis Report Panel for SafeRun
    Displays only filename, threat score, malicious status, and keywords
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.report_data = {}
        self._init_ui()

    def _init_ui(self):
        """Initialize the UI components."""
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        # Title
        self.report_title = QLabel("Analysis Report")
        self.report_title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        main_layout.addWidget(self.report_title)

        # Tree view for report contents
        self.report_tree = QTreeWidget()
        self.report_tree.setHeaderLabels(["Field", "Value"])
        self.report_tree.setColumnWidth(0, 200)
        main_layout.addWidget(self.report_tree)

    def display_report(self, report_data):
        """
        Display the report data in a minimal format.

        Args:
            report_data (dict): The report data to display
        """
        self.report_data = report_data

        print("[Analysis Report Output]")
        print(json.dumps(report_data, indent=2))

        # Clear previous contents
        self.report_tree.clear()

        # Title
        file_name = report_data.get("filename", "Unknown")
        self.report_title.setText(f"Analysis Report: {file_name}")

        # Threat score and verdict
        threat_score = report_data.get("threat_level", 0.0)
        is_malicious = "Yes" if threat_score >= 0.6 else "No"

        self.report_tree.addTopLevelItem(QTreeWidgetItem(["File Name", file_name]))
        self.report_tree.addTopLevelItem(QTreeWidgetItem(["Threat Score", f"{threat_score:.2f}"]))
        self.report_tree.addTopLevelItem(QTreeWidgetItem(["Malicious", is_malicious]))

        # Extract keywords
        keywords = []
        threats = report_data.get("threat_analysis", {}).get("threats", [])
        for t in threats:
            if "signature_name" in t:
                keywords.append(t["signature_name"])
            elif "type" in t:
                keywords.append(t["type"])

        if keywords:
            keywords_node = QTreeWidgetItem(["Detected Keywords", ""])
            for kw in keywords:
                keywords_node.addChild(QTreeWidgetItem(["Keyword", kw]))
            self.report_tree.addTopLevelItem(keywords_node)
