import os
import platform
import yaml
from pathlib import Path

# Base directories
HOME_DIR = str(Path.home())
APP_DIR = os.path.join(HOME_DIR, ".saferun")
SANDBOX_DIR = os.path.join(APP_DIR, "sandbox")
LOG_DIR = os.path.join(APP_DIR, "logs")
REPORT_DIR = os.path.join(APP_DIR, "reports")
TEMP_DIR = os.path.join(APP_DIR, "temp")
CONFIG_FILE = os.path.join(APP_DIR, "config", "sandbox_config.yaml")

# Platform-specific settings
PLATFORM = platform.system()

# Default security levels
SECURITY_LEVELS = {
    "low": {
        "network_access": True,
        "file_system_access": True,
        "registry_access": True,
        "process_creation": True,
    },
    "medium": {
        "network_access": True,
        "file_system_access": True,
        "registry_access": False,
        "process_creation": False,
    },
    "high": {
        "network_access": False,
        "file_system_access": False,
        "registry_access": False,
        "process_creation": False,
    }
}

# File types and extensions
EXECUTABLE_EXTENSIONS = {
    "Windows": [".exe", ".bat", ".cmd", ".msi", ".ps1", ".vbs"],
    "Linux": [".sh", ".bin", ".run", ".AppImage"],
    "Darwin": [".app", ".sh", ".command", ".tool"]
}

DOCUMENT_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]
SCRIPT_EXTENSIONS = [".js", ".py", ".pl", ".rb", ".php"]


# Initialize app directories
def init_directories():
    for directory in [APP_DIR, SANDBOX_DIR, LOG_DIR, REPORT_DIR, TEMP_DIR, os.path.dirname(CONFIG_FILE)]:
        os.makedirs(directory, exist_ok=True)


# Load configuration from YAML
def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_default_config()

    with open(CONFIG_FILE, 'r') as file:
        return yaml.safe_load(file)


# Save default configuration
def save_default_config():
    config = {
        "sandbox": {
            "default_security_level": "medium",
            "isolation_method": "container",  # Options: container, process, virtual
            "auto_detect_downloads": True,
            "watched_directories": [
                os.path.join(HOME_DIR, "Downloads"),
                os.path.join(HOME_DIR, "Desktop")
            ],
            "max_execution_time": 300,  # seconds
            "resource_limits": {
                "cpu_percent": 50,
                "memory_mb": 1024,
                "disk_mb": 1024
            }
        },
        "monitoring": {
            "log_level": "INFO",
            "encrypt_logs": True,
            "monitor_network": True,
            "monitor_file_access": True,
            "monitor_registry": True,
            "monitor_process_activity": True
        },
        "threat_detection": {
            "use_ai_detection": True,
            "signature_checking": True,
            "behavior_analysis": True,
            "detection_sensitivity": 0.7  # 0.0 to 1.0
        },
        "ui": {
            "theme": "light",  # light or dark
            "show_notifications": True,
            "default_view": "simple",  # simple or advanced
            "report_format": "html"
        }
    }

    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as file:
        yaml.dump(config, file, default_flow_style=False)

    return config


# ✅ Added this to fix the missing reference error
def get_temp_dir():
    return TEMP_DIR
