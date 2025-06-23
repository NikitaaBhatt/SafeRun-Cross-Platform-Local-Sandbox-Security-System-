# === Corrected windows.py ===
import os
import sys
import logging
import subprocess
import tempfile
from ctypes import windll

if not sys.platform.startswith('win'):
    raise ImportError("This module should only be imported on Windows systems")


class WindowsContainerHandler:
    def __init__(self):
        self.logger = logging.getLogger("windows-container")

    @staticmethod
    def check_container_support():
        try:
            result = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def create_container(self, security_level, memory_limit, cpu_limit, network_access, security_opts=None):
        try:
            cmd = [
                "docker", "run", "-d",
                "--memory", f"{memory_limit}m",
                "--cpus", f"{cpu_limit / 100}"
            ]
            if not network_access or security_level == "high":
                cmd.append("--network=none")

            cmd += ["mcr.microsoft.com/windows/servercore:ltsc2019", "ping", "-t", "localhost"]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to create Windows container: {str(e)}")
            return None

    def copy_to_container(self, container_id, file_path):
        try:
            filename = os.path.basename(file_path)
            container_path = f"C:\\sandbox\\{filename}"

            subprocess.run(["docker", "exec", container_id, "mkdir", "C:\\sandbox"], capture_output=True, check=False)
            subprocess.run(["docker", "cp", file_path, f"{container_id}:C:\\sandbox"], capture_output=True, check=True)

            return container_path
        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to copy file to container: {str(e)}")
            raise RuntimeError("File transfer to container failed")

    def execute_in_container(self, container_id, container_path, args):
        try:
            cmd = ["docker", "exec", container_id, container_path] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Execution timed out", "exit_code": -1}
        except subprocess.SubprocessError as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

    def remove_container(self, container_id):
        try:
            subprocess.run(["docker", "stop", container_id], capture_output=True, check=False)
            subprocess.run(["docker", "rm", container_id], capture_output=True, check=True)
            return True
        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to remove container: {str(e)}")
            return False


class WindowsProcessHandler:
    def __init__(self):
        self.logger = logging.getLogger("windows-process")

    @staticmethod
    def check_isolation_support():
        return True

    def initialize(self, security_level, memory_limit=None, cpu_limit=None, network_access=None, io_priority=None, temp_dir=None):
        try:
            if not windll.shell32.IsUserAnAdmin():
                self.logger.warning("Process isolation works best with administrator privileges")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize process isolation: {str(e)}")
            return False

    def execute_isolated(self, file_path, args, security_level, working_dir=None):
        try:
            with tempfile.NamedTemporaryFile(suffix='.bat', delete=False, mode='w') as f:
                batch_path = f.name
                f.write(f'@echo off\n"{file_path}" {" ".join(args)}\n')

            if self._is_windows_sandbox_available() and security_level != "low":
                return self._execute_in_windows_sandbox(batch_path)

            process = subprocess.Popen(
                [file_path] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=working_dir,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )

            try:
                stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()

            return process, {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": process.returncode
            }
        except Exception as e:
            self.logger.error(f"Error during isolated execution: {str(e)}")
            return None, {"stdout": "", "stderr": str(e), "exit_code": -1}
        finally:
            if os.path.exists(batch_path):
                os.unlink(batch_path)

    @staticmethod
    def terminate_process(process):
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                process.kill()

    @staticmethod
    def _is_windows_sandbox_available():
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM'"],
                capture_output=True, text=True
            )
            return "Enabled" in result.stdout
        except subprocess.SubprocessError:
            return False

    @staticmethod
    def _execute_in_windows_sandbox(batch_path):
        with tempfile.NamedTemporaryFile(suffix='.wsb', delete=False, mode='w') as f:
            wsb_path = f.name
            f.write(f"""<Configuration>
                <MappedFolders>
                    <MappedFolder>
                        <HostFolder>{os.path.dirname(batch_path)}</HostFolder>
                        <ReadOnly>true</ReadOnly>
                    </MappedFolder>
                </MappedFolders>
                <LogonCommand>
                    <Command>{os.path.basename(batch_path)}</Command>
                </LogonCommand>
            </Configuration>""")

        try:
            process = subprocess.Popen(
                ["WindowsSandbox", wsb_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return process, {
                "stdout": "Executed in Windows Sandbox - output not available",
                "stderr": "",
                "exit_code": 0
            }
        finally:
            if os.path.exists(wsb_path):
                os.unlink(wsb_path)
