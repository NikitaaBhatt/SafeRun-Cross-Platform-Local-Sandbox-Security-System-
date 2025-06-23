import os
import platform
import psutil
import shutil
import subprocess
import logging
from pathlib import Path
import tempfile
import uuid

logger = logging.getLogger(__name__)

def get_system_info():
    """Get basic system information."""
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "ram_total": psutil.virtual_memory().total,
        "ram_available": psutil.virtual_memory().available
    }

def check_platform_support():
    """Check if current platform is supported."""
    system = platform.system().lower()
    return system in ["windows", "linux", "darwin"]

def create_temp_directory():
    """Create a temporary directory for safe execution."""
    temp_dir = Path(tempfile.gettempdir()) / f"saferun_{uuid.uuid4().hex}"
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

def clean_temp_directory(directory):
    """Safely remove a temporary directory."""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory, ignore_errors=True)
            return True
    except Exception as e:
        logger.error(f"Failed to clean temp directory {directory}: {e}")
        return False
    return False

def is_admin():
    """Check if the current process has administrator/root privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_process_info(pid):
    """Get detailed information about a running process."""
    try:
        process = psutil.Process(pid)
        return {
            "pid": pid,
            "name": process.name(),
            "status": process.status(),
            "created_time": process.create_time(),
            "cpu_percent": process.cpu_percent(),
            "memory_percent": process.memory_percent(),
            "executable": process.exe(),
            "command_line": process.cmdline(),
            "open_files": [f.path for f in process.open_files()],
            "connections": [c._asdict() for c in process.connections()],
            "threads": process.num_threads()
        }
    except psutil.NoSuchProcess:
        return {"error": f"Process with PID {pid} not found"}
    except Exception as e:
        return {"error": str(e)}

def kill_process(pid):
    """Kill a process by its PID."""
    try:
        process = psutil.Process(pid)
        process.kill()
        return True
    except Exception as e:
        logger.error(f"Failed to kill process {pid}: {e}")
        return False

def execute_command(command, timeout=60, shell=False):
    """Execute a system command safely."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command execution timed out", "success": False}
    except Exception as e:
        return {"error": str(e), "success": False}

def get_open_ports():
    """Get a list of open network ports on the system."""
    connections = psutil.net_connections()
    open_ports = []
    
    for conn in connections:
        if conn.status == 'LISTEN':
            open_ports.append({
                "port": conn.laddr.port,
                "address": conn.laddr.ip,
                "pid": conn.pid,
                "protocol": "TCP"  # psutil typically reports TCP
            })
    
    return open_ports

def get_disk_usage(path=None):
    """Get disk usage information."""
    if path is None:
        path = os.getcwd()
    
    return shutil.disk_usage(path)._asdict()

def check_file_permissions(filepath):
    """Check file permissions."""
    if not os.path.exists(filepath):
        return {"error": "File does not exist"}
    
    try:
        stats = os.stat(filepath)
        return {
            "exists": True,
            "permissions": oct(stats.st_mode)[-3:],
            "owner": stats.st_uid,
            "group": stats.st_gid,
            "size": stats.st_size,
            "is_readable": os.access(filepath, os.R_OK),
            "is_writable": os.access(filepath, os.W_OK),
            "is_executable": os.access(filepath, os.X_OK)
        }
    except Exception as e:
        return {"error": str(e)}
