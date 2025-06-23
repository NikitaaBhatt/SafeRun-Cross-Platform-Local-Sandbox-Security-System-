import os
import sys
import logging
import subprocess
import tempfile
import shutil

# Check if we're running on Linux
if not sys.platform.startswith('linux'):
    raise ImportError("This module should only be imported on Linux systems")


class LinuxContainerHandler:
    """Handles container operations for Linux systems"""

    def __init__(self):
        self.logger = logging.getLogger("linux-container")

    @staticmethod
    def check_container_support():
        """Check if Docker or similar container tech is available"""
        for cmd in ["docker", "podman"]:
            try:
                result = subprocess.run([cmd, "version"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        return False

    def create_container(self, security_level, memory_limit, cpu_limit, network_access):
        """Create a Linux container for isolation"""
        try:
            container_cmd = self._get_container_command()
            if not container_cmd:
                raise RuntimeError("No container runtime found")

            cmd = [
                container_cmd, "run", "-d",
                "--memory", f"{memory_limit}m",
                "--cpus", f"{cpu_limit / 100}"
            ]

            if not network_access or security_level == "high":
                cmd.append("--network=none")

            if security_level == "high":
                cmd.extend(["--cap-drop=ALL", "--security-opt=no-new-privileges"])
            elif security_level == "medium":
                cmd.extend(["--cap-drop=NET_ADMIN", "--cap-drop=SYS_ADMIN"])

            cmd.append("alpine:latest")
            cmd.extend(["tail", "-f", "/dev/null"])

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()

        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to create Linux container: {str(e)}")
            return None

    def copy_to_container(self, container_id, file_path):
        """Copy a file to the container"""
        try:
            container_cmd = self._get_container_command()
            filename = os.path.basename(file_path)
            container_path = f"/sandbox/{filename}"

            subprocess.run([container_cmd, "exec", container_id, "mkdir", "-p", "/sandbox"], capture_output=True,
                           check=True)
            subprocess.run([container_cmd, "cp", file_path, f"{container_id}:/sandbox/"], capture_output=True,
                           check=True)
            subprocess.run([container_cmd, "exec", container_id, "chmod", "+x", container_path], capture_output=True,
                           check=True)

            return container_path

        except subprocess.SubprocessError as e:
            self.logger.error(f"Failed to copy file to container: {str(e)}")
            raise RuntimeError("File transfer to container failed")

    @staticmethod
    def _get_container_command():
        """Determine which container runtime to use"""
        for cmd in ["docker", "podman"]:
            try:
                result = subprocess.run([cmd, "--version"], capture_output=True, timeout=2)
                if result.returncode == 0:
                    return cmd
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        return None


class LinuxProcessHandler:
    """Handles process isolation for Linux systems"""

    def __init__(self):
        self.logger = logging.getLogger("linux-process")
        self.firejail_available = self._check_firejail()
        self.bubblewrap_available = self._check_bubblewrap()

    def check_isolation_support(self):
        """Check if process isolation is supported"""
        return self.firejail_available or self.bubblewrap_available

    @staticmethod
    def _check_firejail():
        """Check if Firejail is available"""
        try:
            result = subprocess.run(["firejail", "--version"], capture_output=True, timeout=2)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    @staticmethod
    def _check_bubblewrap():
        """Check if Bubblewrap is available"""
        try:
            result = subprocess.run(["bwrap", "--version"], capture_output=True, timeout=2)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    @staticmethod
    def _execute_basic_isolation(file_path, args):
        """Execute with basic isolation when no sandboxing tools are available"""
        temp_dir = tempfile.mkdtemp(prefix="saferun_basic_")
        try:
            target_file = os.path.basename(file_path)
            target_path = os.path.join(temp_dir, target_file)
            shutil.copy2(file_path, target_path)
            os.chmod(target_path, 0o755)

            cmd = [target_path] + args
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=30)

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": process.returncode
            }

        except subprocess.SubprocessError as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @staticmethod
    def terminate_process(process):
        """Terminate an isolated process"""
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                process.kill()
