import os
import time
import json
import psutil
import threading
import platform
from datetime import datetime

from saferun.config import settings
from saferun.utils.logger import LogManager


class ProcessMonitor:
    def __init__(self, sandbox_id):
        self.logger = LogManager().get_logger("monitor")
        self.sandbox_id = sandbox_id
        self.platform = platform.system()
        self.monitoring = False
        self.monitoring_thread = None
        self.log_dir = os.path.join(settings.LOG_DIR, sandbox_id)
        os.makedirs(self.log_dir, exist_ok=True)

        self.pid = None
        self.threat_score = 0
        self.monitoring_data = {
            "file_accesses": [],
            "network_connections": [],
            "registry_activities": [],
        }

        self.suspicious_patterns = {
            "files": ["C:\\Windows\\System32\\config", "/etc/passwd"],
            "network": ["malicious.example.com", ":4444", ":1337", ":31337"],
            "registry": [
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ]
        }

        self.logger.info(f"Process monitor initialized for sandbox {sandbox_id}")

    def start_monitoring(self, pid):
        if not pid:
            self.logger.error("No PID provided for monitoring")
            return self.monitoring_data

        self.pid = pid
        try:
            process = psutil.Process(self.pid)
            if not process.is_running():
                self.logger.error(f"Process {self.pid} is not running")
                return self.monitoring_data
        except psutil.NoSuchProcess:
            self.logger.error(f"Process {self.pid} not found")
            return self.monitoring_data

        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitor_process)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

        self.logger.info(f"Started monitoring process {pid}")
        return self.monitoring_data

    def stop_monitoring(self):
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)

        self.monitoring_data["threat_score"] = self.threat_score
        log_file = os.path.join(self.log_dir, f"monitor_{self.pid}.json")
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(self.monitoring_data, f)

        self.logger.info(f"Stopped monitoring process {self.pid}, log saved to {log_file}")

        # Rename keys to match threat_detector
        self.monitoring_data["file_operations"] = self.monitoring_data.pop("file_accesses", [])
        self.monitoring_data["network_activity"] = self.monitoring_data.pop("network_connections", [])
        self.monitoring_data["registry_operations"] = self.monitoring_data.pop("registry_activities", [])

        # ✅ ADDED: Print to console for Process Monitor section
        print("\n[Process Monitor Output]")
        print(json.dumps(self.monitoring_data, indent=2))

        return self.monitoring_data

    def _monitor_process(self):
        try:
            process = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            self.logger.error(f"Process {self.pid} not found during monitoring")
            self.monitoring = False
            return

        while self.monitoring:
            try:
                if not process.is_running():
                    self.logger.info(f"Process {self.pid} has terminated")
                    break

                self._monitor_file_activity(process)
                self._monitor_network_activity(process)
                if self.platform == "Windows":
                    self._monitor_registry_activity(process)

                time.sleep(1)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as e:
                self.logger.error(f"Error monitoring process: {e}")
                break

    def _monitor_file_activity(self, process):
        try:
            for file in process.open_files():
                path = file.path
                if not any(f["path"] == path for f in self.monitoring_data["file_accesses"]):
                    self.monitoring_data["file_accesses"].append({
                        "timestamp": datetime.now().isoformat(),
                        "path": path
                    })
                    for pattern in self.suspicious_patterns["files"]:
                        if pattern in path:
                            self.threat_score += 10
        except Exception:
            pass

    def _monitor_network_activity(self, process):
        try:
            for conn in process.connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                    if not any(n["remote"] == remote for n in self.monitoring_data["network_connections"]):
                        self.monitoring_data["network_connections"].append({
                            "timestamp": datetime.now().isoformat(),
                            "remote": remote
                        })
                    for pattern in self.suspicious_patterns["network"]:
                        if pattern in remote:
                            self.threat_score += 20
        except Exception:
            pass

    def _monitor_registry_activity(self, process):
        try:
            dlls = process.memory_maps()
            for dll in dlls:
                path = dll.path.lower()
                if "advapi32.dll" in path:
                    if not any(r.get("dll") == path for r in self.monitoring_data["registry_activities"]):
                        self.monitoring_data["registry_activities"].append({
                            "timestamp": datetime.now().isoformat(),
                            "dll": path,
                            "key": self.suspicious_patterns["registry"][0]
                        })
                        self.threat_score += 5
        except Exception:
            pass
