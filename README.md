# SafeRun: Cross-Platform Local Sandbox Security System

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/NikitaaBhatt/SafeRun-Cross-Platform-Local-Sandbox-Security-System-)

SafeRun is a comprehensive cross-platform sandbox security system that allows you to safely execute potentially malicious files in an isolated environment. It provides real-time threat detection, behavioral analysis, and detailed security reports to help you analyze file safety before execution.

## 🚀 Features

### Core Security Features
- **Multi-level Isolation**: Container-based and process-based isolation methods
- **Real-time Threat Detection**: Advanced behavioral analysis with signature-based detection
- **Cross-Platform Support**: Native support for Windows, Linux, and macOS
- **Configurable Security Levels**: Low, Medium, and High security profiles
- **Comprehensive File Analysis**: Static analysis with hash generation and risk assessment

### Advanced Capabilities
- **Process Monitoring**: Real-time monitoring of file operations, network activity, and system calls
- **Threat Intelligence**: Built-in threat signatures with custom signature support
- **Resource Management**: CPU, memory, and network restrictions based on security level
- **Detailed Reporting**: Comprehensive execution reports with threat analysis

### User Interface
- **GUI Application**: Modern PyQt6-based graphical interface
- **Command Line Interface**: Full CLI support for automation and scripting
- **Real-time Monitoring**: Live monitoring dashboard with visual threat indicators

## 📋 Requirements

### System Requirements
- **Operating System**: Windows 10+, Linux (Ubuntu 18.04+), or macOS 10.14+
- **Python**: 3.10 or 3.11 (Python 3.12 not yet supported)
- **Docker**: Required for container-based isolation
- **Memory**: Minimum 4GB RAM recommended
- **Disk Space**: At least 2GB free space

### Dependencies
- PyQt6 for GUI components
- Docker SDK for container management
- psutil for system monitoring
- PyYAML for configuration management
- Additional dependencies listed in `requirements.txt`

## 🔧 Installation

### Method 1: Using pip (Recommended)
```bash
# Clone the repository
git clone https://github.com/NikitaaBhatt/SafeRun-Cross-Platform-Local-Sandbox-Security-System-.git
cd SafeRun-Cross-Platform-Local-Sandbox-Security-System-

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install SafeRun
pip install -e .
```

### Method 2: Development Installation
```bash
# Clone and setup development environment
git clone https://github.com/NikitaaBhatt/SafeRun-Cross-Platform-Local-Sandbox-Security-System-.git
cd SafeRun-Cross-Platform-Local-Sandbox-Security-System-

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .[dev]
```

### Docker Setup
SafeRun requires Docker for container-based isolation:

```bash
# Install Docker Desktop (Windows/macOS)
# Visit: https://www.docker.com/products/docker-desktop

# Install Docker Engine (Linux)
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

## 🎯 Quick Start

### GUI Mode
```bash
# Launch SafeRun GUI
saferun --gui

# Or simply (GUI is default when no file specified)
saferun
```

### Command Line Mode
```bash
# Analyze a file with default settings
saferun suspicious_file.py

# Specify security level and isolation method
saferun --security high --isolation container malware_sample.exe

# Force CLI mode
saferun --cli --security medium script.py
```

### Example Usage
```bash
# High security analysis of a Python script
saferun --security high --isolation container suspicious_script.py

# Quick analysis with process isolation
saferun --security low --isolation process test_file.py

# GUI mode for interactive analysis
saferun --gui
```

## 🛡️ Security Levels

### Low Security
- **Use Case**: Trusted files, development testing
- **Isolation**: Basic process isolation
- **Resources**: 512MB RAM, 50% CPU, network access allowed
- **Monitoring**: Basic file operations

### Medium Security (Default)
- **Use Case**: Unknown files, general analysis
- **Isolation**: Container or enhanced process isolation
- **Resources**: 256MB RAM, 30% CPU, no network access
- **Monitoring**: Comprehensive system monitoring

### High Security
- **Use Case**: Suspected malware, maximum protection
- **Isolation**: Strict container isolation
- **Resources**: 128MB RAM, 15% CPU, no network access
- **Monitoring**: Full behavioral analysis with detailed logging

## 📊 Understanding Reports

SafeRun generates comprehensive reports including:

- **File Analysis**: Hash, type, size, and static analysis results
- **Execution Status**: Success, failure, timeout, or blocked
- **Threat Detection**: Identified threats with severity levels
- **Resource Usage**: CPU, memory, and network activity
- **Behavioral Analysis**: File operations, process creation, registry access

### Threat Levels
- **NONE (0)**: No threats detected
- **LOW (1)**: Minor suspicious activity
- **MEDIUM (2)**: Potentially dangerous behavior
- **HIGH (3)**: Likely malicious activity
- **CRITICAL (4)**: Definite malware detection

## 🔧 Configuration

SafeRun uses YAML configuration files located in `saferun/config/`:

```yaml
# sandbox_config.yaml example
sandbox:
  default_security_level: "medium"
  isolation_method: "container"
  timeout: 300
  
security_levels:
  high:
    memory_limit: "128m"
    cpu_percent: 15
    network_access: false
```

## 🏗️ Project Structure

```
SafeRun/
├── saferun/
│   ├── main.py              # Entry point
│   ├── config/              # Configuration files
│   ├── core/                # Core security components
│   │   ├── sandbox.py       # Main sandbox orchestrator
│   │   ├── threat_detector.py # Threat detection engine
│   │   ├── monitor.py       # Process monitoring
│   │   └── isolation.py     # Isolation mechanisms
│   ├── platforms/           # Platform-specific implementations
│   ├── utils/               # Utility modules
│   └── gui/                 # GUI components
├── tests/                   # Test suite
└── requirements.txt         # Dependencies
```

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run specific test modules
pytest tests/test_sandbox.py
pytest tests/test_threat_detector.py

# Run with coverage
pytest --cov=saferun tests/
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/NikitaaBhatt/SafeRun-Cross-Platform-Local-Sandbox-Security-System-.git
cd SafeRun-Cross-Platform-Local-Sandbox-Security-System-
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```


## 👥 Authors

- **CodeCrafters Team** - *Initial work* - [nikkitabhatt1020@gmail.com](mailto:nikkitabhatt1020@gmail.com)

## 🙏 Acknowledgments

- Docker for containerization technology
- PyQt6 for the graphical user interface
- The Python security community for threat intelligence insights

## 📞 Support

For support, email nikkitabhatt1020@gmail.com or create an issue on GitHub.

## 🔄 Changelog

### Version 0.1.0
- Initial release
- Core sandbox functionality
- GUI and CLI interfaces
- Cross-platform support
- Basic threat detection

---

**⚠️ Disclaimer**: SafeRun is designed for security analysis and educational purposes. Always exercise caution when dealing with potentially malicious files. The authors are not responsible for any damage caused by misuse of this software.
