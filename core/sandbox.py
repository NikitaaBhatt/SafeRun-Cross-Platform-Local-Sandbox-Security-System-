import os
import time
import uuid
import shutil
import subprocess
from datetime import datetime

from saferun.config import settings
from saferun.core.monitor import ProcessMonitor
from saferun.core.threat_detector import ThreatDetector
from saferun.utils.file_analyzer import FileAnalyzer
from saferun.utils.logger import LogManager
from saferun.core.isolation import get_isolation_environment


class Sandbox:
    def __init__(self, isolation_method="container", security_level="medium"):
        self.logger = LogManager().get_logger("sandbox")
        self.security_level = security_level
        self.isolation_method = isolation_method
        self.sandbox_id = str(uuid.uuid4())
        self.sandbox_dir = os.path.join(settings.SANDBOX_DIR, self.sandbox_id)
        self.file_analyzer = FileAnalyzer()
        self.threat_detector = ThreatDetector(security_level, isolation_method)
        self.process_monitor = ProcessMonitor(self.sandbox_id)
        self.isolation_env = get_isolation_environment(isolation_method, security_level)

        os.makedirs(self.sandbox_dir, exist_ok=True)
        self.logger.info(f"Sandbox initialized with ID: {self.sandbox_id} using {isolation_method} isolation")

    def _prepare_file(self, file_path):
        dest_dir = os.path.join(self.sandbox_dir, "files")
        os.makedirs(dest_dir, exist_ok=True)
        file_name = os.path.basename(file_path)
        dest_file_path = os.path.join(dest_dir, file_name)
        shutil.copy(file_path, dest_file_path)
        return dest_file_path

    def _execute_in_container(self, file_path, timeout):
        try:
            result = self.isolation_env.execute(file_path)
            return {
                "status": "completed",
                "exit_code": result.get("exit_code", 0),
                "pid": result.get("pid"),
                "process": None
            }
        except Exception as e:
            self.logger.error(f"Container execution failed: {e}")
            return {
                "status": "failed",
                "exit_code": -1,
                "pid": None,
                "process": None
            }

    def _execute_in_process(self, file_path, timeout):
        try:
            process, output = self.isolation_env.execute(file_path)
            return {
                "status": "completed",
                "exit_code": 0,
                "pid": process.pid if process else None,
                "process": process
            }
        except Exception as e:
            self.logger.error(f"Process execution failed: {e}")
            return {
                "status": "failed",
                "exit_code": -1,
                "pid": None,
                "process": None
            }

    def _terminate_execution(self, execution_result):
        process = execution_result.get("process")
        if process:
            try:
                process.terminate()
                self.logger.info(f"Terminated process {process.pid}")
            except Exception as e:
                self.logger.warning(f"Failed to terminate process: {e}")

    def execute_file(self, file_path, timeout=300, monitor=True):
        start_time = time.time()

        # ✅ Static analysis
        analysis_result = self.file_analyzer.analyze(file_path)
        static_threat_score = analysis_result.get("threat_level", 0.0)
        static_threats = analysis_result.get("threat_analysis", {}).get("threats", [])
        file_name = analysis_result.get("filename", os.path.basename(file_path))

        # Copy to sandbox directory
        sandbox_file_path = self._prepare_file(file_path)

        # Elevate security if static score is high
        if static_threat_score > 0.2:
            self.security_level = "high"

        # ✅ Execute in sandbox
        if self.isolation_method == "container":
            execution_result = self._execute_in_container(sandbox_file_path, timeout)
            monitor_results = {}
        else:
            execution_result = self._execute_in_process(sandbox_file_path, timeout)
            monitor_results = {}
            if monitor and execution_result.get("pid"):
                self.process_monitor.start_monitoring(execution_result.get("pid"))
                if execution_result.get("process"):
                    try:
                        execution_result["process"].wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        self._terminate_execution(execution_result)

                # ✅ Monitor output
                monitor_results = self.process_monitor.stop_monitoring()

                # ✅ Print to console
                import json
                print("\n[Process Monitor Output]")
                print(json.dumps(monitor_results, indent=2))

        # ✅ Dynamic analysis
        dynamic_analysis = self.threat_detector.analyze_report(monitor_results)
        dynamic_score = dynamic_analysis.get("threat_score", 0)
        dynamic_threats = dynamic_analysis.get("threats", [])

        total_threat_score = round(min(static_threat_score + dynamic_score, 1.0), 2)

        # ✅ Combine static + dynamic threats
        combined_threats = static_threats + dynamic_threats

        # ✅ Build final report
        report = {
            "sandbox_id": self.sandbox_id,
            "filename": file_name,  # ✅ This fixes “Unknown”
            "file": file_name,
            "file_hash": analysis_result.get("file_hash"),
            "execution_time": time.time() - start_time,
            "status": execution_result.get("status", "unknown"),
            "exit_code": execution_result.get("exit_code"),
            "threat_level": total_threat_score,
            "monitoring_results": monitor_results,
            "threat_analysis": {
                "threats": combined_threats
            },
            "timestamp": datetime.now().isoformat(),

            # For GUI tabs (can be safely ignored by minimal GUI)
            "file_operations": monitor_results.get("file_operations", []),
            "network_activity": monitor_results.get("network_activity", []),
            "registry_operations": monitor_results.get("registry_operations", []),
        }

        self.cleanup()
        self.logger.info(f"Execution completed for file {file_path} with threat score {total_threat_score}")
        return report

    def cleanup(self):
        try:
            if os.path.exists(self.sandbox_dir):
                shutil.rmtree(self.sandbox_dir)
                self.logger.info(f"Temporary files removed from {self.sandbox_dir}")
            self.isolation_env.cleanup()
        except Exception as e:
            self.logger.warning(f"Failed to clean up sandbox: {e}")
