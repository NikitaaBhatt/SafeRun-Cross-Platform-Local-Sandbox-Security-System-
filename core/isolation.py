import os
import platform
import logging
import uuid
from abc import ABC, abstractmethod

from saferun.config import settings

system = platform.system().lower()
if system == "windows":
    from saferun.platforms import windows as platform_module
elif system == "linux":
    from saferun.platforms import linux as platform_module
elif system == "darwin":
    from saferun.platforms import macos as platform_module
else:
    raise ImportError(f"Unsupported OS: {system}")


class IsolationProvider(ABC):
    @abstractmethod
    def setup(self): pass

    @abstractmethod
    def cleanup(self): pass

    @abstractmethod
    def execute(self, file_path, args=None): pass

    @abstractmethod
    def is_available(self): pass


class ContainerIsolation(IsolationProvider):
    def __init__(self, security_level="medium"):
        self.logger = logging.getLogger("container-isolation")
        self.security_level = security_level.lower()
        self.container_id = None
        self.platform_handler = None
        self.isolation_id = str(uuid.uuid4())

        if self.security_level not in ["low", "medium", "high"]:
            self.logger.warning(f"Invalid level '{self.security_level}', defaulting to medium")
            self.security_level = "medium"

        self.platform_handler = platform_module.WindowsContainerHandler() if system == "windows" else (
            platform_module.LinuxContainerHandler() if system == "linux" else platform_module.MacOSContainerHandler()
        )

    def setup(self):
        self.logger.info(f"Setting up container isolation at {self.security_level} level")
        return self._create_container()

    def _create_container(self):
        config = {}
        try:
            config = settings.load_config().get("sandbox", {}).get("resource_limits", {})
        except Exception as e:
            self.logger.warning(f"Failed to load resource config: {e}")

        mem = config.get("memory_mb", {}).get(self.security_level, 256)
        cpu = config.get("cpu_percent", {}).get(self.security_level, 30)
        net = config.get("network_access", {}).get(self.security_level, False)

        try:
            self.container_id = self.platform_handler.create_container(
                security_level=self.security_level,
                memory_limit=mem,
                cpu_limit=cpu,
                network_access=net
            )
            return self.container_id
        except Exception as e:
            self.logger.error(f"Failed to create container: {e}")
            raise RuntimeError("Container creation failed")

    def cleanup(self):
        if self.container_id:
            try:
                self.platform_handler.remove_container(self.container_id)
                self.logger.info(f"Container {self.container_id} removed")
                self.container_id = None
                return True
            except Exception as e:
                self.logger.error(f"Cleanup failed: {e}")
        return False

    def execute(self, file_path, args=None):
        if not self.container_id:
            self.setup()
        return self.platform_handler.execute_in_container(self.container_id, file_path, args or [])

    def is_available(self):
        try:
            return self.platform_handler.check_container_support()
        except Exception:
            return False


class ProcessIsolation(IsolationProvider):
    def __init__(self, security_level="medium"):
        self.logger = logging.getLogger("process-isolation")
        self.security_level = security_level.lower()
        self.platform_handler = None
        self.process = None
        self.isolation_id = str(uuid.uuid4())

        if self.security_level not in ["low", "medium", "high"]:
            self.logger.warning(f"Invalid level '{self.security_level}', defaulting to medium")
            self.security_level = "medium"

        self.platform_handler = platform_module.WindowsProcessHandler() if system == "windows" else (
            platform_module.LinuxProcessHandler() if system == "linux" else platform_module.MacOSProcessHandler()
        )

    def setup(self):
        self.logger.info(f"Setting up process isolation: {self.security_level}")
        return self.platform_handler.initialize(security_level=self.security_level)

    def cleanup(self):
        if self.process:
            try:
                self.platform_handler.terminate_process(self.process)
                self.process = None
                return True
            except Exception as e:
                self.logger.warning(f"Failed to terminate process: {e}")
        return False

    def execute(self, file_path, args=None):
        self.process, output = self.platform_handler.execute_isolated(file_path, args or [], self.security_level)
        return self.process, output

    def is_available(self):
        try:
            return self.platform_handler.check_isolation_support()
        except Exception:
            return False


def get_isolation_environment(method="container", security_level="medium"):
    method = method.lower()
    if method == "container":
        container = ContainerIsolation(security_level)
        if container.is_available():
            return container
        logging.warning("Container isolation not available, trying process isolation...")

    if method == "process" or method == "container":
        process = ProcessIsolation(security_level)
        if process.is_available():
            return process

    raise RuntimeError("No supported isolation method available.")
