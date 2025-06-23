"""
MacOS-specific platform implementation for SafeRun sandbox.
Handles system-specific tasks for isolation, monitoring, and security on macOS systems.
"""

import os
import subprocess
import psutil
import logging
from saferun.core.isolation import IsolationProvider

logger = logging.getLogger(__name__)


class MacOSPlatform(IsolationProvider):
    """MacOS implementation of the platform-specific isolation provider."""

    def __init__(self):
        """Initialize the MacOS platform handler."""
        super().__init__()
        self.platform_name = "macos"
        logger.info("Initializing MacOS platform handler")

    @staticmethod
    def check_prerequisites():
        """
        Check if all required prerequisites for MacOS sandboxing are available.

        Returns:
            bool: True if all prerequisites are met, False otherwise
        """
        # Check if Docker is installed and running
        try:
            docker_info = subprocess.run(['docker', 'info'], capture_output=True, text=True)
            if docker_info.returncode != 0:
                logger.error("Docker is not running. Please start Docker Desktop.")
                return False

            logger.info("Docker is available and running")

            # Check for XPC permissions for sandboxing
            xpc_check = subprocess.run(['csrutil', 'status'], capture_output=True, text=True)
            logger.info(f"System Integrity Protection status: {xpc_check.stdout.strip()}")

            return True
        except FileNotFoundError as e:
            logger.error(f"Docker is not installed. Please install Docker Desktop for Mac. Error: {e}")
            return False

    @staticmethod
    def create_sandbox(config):
        """
        Create a sandboxed environment for running untrusted code.

        Args:
            config (dict): Configuration settings for the sandbox

        Returns:
            str: Sandbox ID if successful, None otherwise
        """
        logger.info("Creating macOS sandbox with config: %s", config)

        # Check if we should use Docker or native sandbox
        if config.get('use_docker', True):
            # Use Docker for stronger isolation
            image_name = config.get('docker_image', 'alpine:latest')
            container_name = f"saferun_sandbox_{os.getpid()}"

            try:
                cmd = [
                    'docker', 'run', '-d', '--name', container_name,
                    '--memory', config.get('memory_limit', '512m'),
                    '--cpus', str(config.get('cpu_limit', 1)),
                    '--network', config.get('network_mode', 'none'),
                    image_name
                ]

                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                sandbox_id = result.stdout.strip()
                logger.info(f"Created Docker sandbox with ID: {sandbox_id}")
                return sandbox_id
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to create Docker sandbox: {e}")
                return None
        else:
            # Use macOS native sandboxing (limited capabilities)
            logger.warning("Native macOS sandboxing has limited capabilities")
            return f"native_sandbox_{os.getpid()}"

    def run_in_sandbox(self, sandbox_id, command, timeout=30):
        """
        Execute a command inside the sandbox.

        Args:
            sandbox_id (str): ID of the sandbox to use
            command (list): Command to execute as a list of strings
            timeout (int): Maximum execution time in seconds

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        if sandbox_id.startswith("native_sandbox_"):
            # For native sandbox, we use the macOS sandbox-exec command
            sandboxed_cmd = ['sandbox-exec', '-f', self._get_sandbox_profile()]
            sandboxed_cmd.extend(command)

            try:
                result = subprocess.run(
                    sandboxed_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired:
                logger.warning(f"Command timed out after {timeout} seconds")
                return "", "Execution timed out", -1
            except subprocess.SubprocessError as e:
                logger.exception(f"Error executing command in native sandbox: {e}")
                return "", str(e), -1
        else:
            # For Docker sandbox
            docker_cmd = [
                'docker', 'exec', sandbox_id, 'sh', '-c', ' '.join(command)
            ]

            try:
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired:
                logger.warning(f"Docker command timed out after {timeout} seconds")
                return "", "Execution timed out", -1
            except subprocess.SubprocessError as e:
                logger.exception(f"Error executing command in Docker sandbox: {e}")
                return "", str(e), -1

    @staticmethod
    def destroy_sandbox(sandbox_id):
        """
        Clean up and destroy the sandbox.

        Args:
            sandbox_id (str): ID of the sandbox to destroy

        Returns:
            bool: True if successful, False otherwise
        """
        if sandbox_id.startswith("native_sandbox_"):
            logger.info(f"Cleaned up native sandbox {sandbox_id}")
            return True
        else:
            # For Docker sandbox
            try:
                # First stop the container
                subprocess.run(['docker', 'stop', sandbox_id], capture_output=True, check=True)

                # Then remove it
                subprocess.run(['docker', 'rm', sandbox_id], capture_output=True, check=True)

                logger.info(f"Successfully destroyed Docker sandbox {sandbox_id}")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to destroy Docker sandbox {sandbox_id}: {e}")
                return False

    @staticmethod
    def monitor_resource_usage(sandbox_id):
        """
        Get current resource usage for the sandbox.

        Args:
            sandbox_id (str): ID of the sandbox to monitor

        Returns:
            dict: Resource usage metrics
        """
        metrics = {
            'cpu_percent': 0,
            'memory_usage': 0,
            'memory_percent': 0,
            'disk_io': 0,
            'network_io': 0
        }

        if sandbox_id.startswith("native_sandbox_"):
            pid = int(sandbox_id.split('_')[-1])
            try:
                process = psutil.Process(pid)
                metrics['cpu_percent'] = process.cpu_percent(interval=0.1)
                memory_info = process.memory_info()
                metrics['memory_usage'] = memory_info.rss
                metrics['memory_percent'] = process.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning(f"Could not monitor process {pid}: {e}")
        else:
            # For Docker sandbox
            try:
                stats_cmd = ['docker', 'stats', '--no-stream', '--format',
                             '{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.BlockIO}}\t{{.NetIO}}',
                             sandbox_id]

                result = subprocess.run(stats_cmd, capture_output=True, text=True, check=True)

                if result.stdout.strip():
                    stats = result.stdout.strip().split('\t')
                    if len(stats) >= 5:
                        metrics['cpu_percent'] = float(stats[0].replace('%', ''))
                        metrics['memory_percent'] = float(stats[2].replace('%', ''))
                        metrics['disk_io'] = stats[3]
                        metrics['network_io'] = stats[4]
            except subprocess.CalledProcessError as e:
                logger.exception(f"Error monitoring Docker sandbox {sandbox_id}: {e}")

        return metrics

    @staticmethod
    def _get_sandbox_profile():
        """
        Get the path to the sandbox profile for macOS native sandboxing.

        Returns:
            str: Path to the sandbox profile
        """
        profile_path = os.path.join(os.path.dirname(__file__), "..", "config", "macos_sandbox.sb")
        return profile_path
