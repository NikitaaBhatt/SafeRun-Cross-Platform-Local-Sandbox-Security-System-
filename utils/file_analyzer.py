import os
import hashlib
import re
from saferun.config import settings
from saferun.utils.logger import LogManager


class FileAnalyzer:
    def __init__(self):
        self.logger = LogManager().get_logger("file_analyzer")

    def analyze(self, file_path):
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return {"error": "File not found", "threat_level": 0.0}

        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()

            md5_hash = self._calculate_hash(file_path, "md5")
            sha256_hash = self._calculate_hash(file_path, "sha256")

            file_type = f"Unknown (extension: {file_ext})"
            threat_score = 0.0
            threats = []

            is_executable = self._is_executable(file_path, file_ext)
            if is_executable:
                threat_score += 0.3
                threats.append({
                    "signature_name": "Executable file detected",
                    "threat_level": 0.3,
                    "details": "The file is an executable, which could perform system-level operations."
                })

            if file_ext in [".sh", ".py", ".bat", ".ps1"]:
                threat_score += 0.1
                threats.append({
                    "signature_name": "Script file detected",
                    "threat_level": 0.1,
                    "details": "Script files may contain commands that alter system behavior."
                })

                suspicious_patterns = self._check_script_for_suspicious_patterns(file_path)
                for pattern in suspicious_patterns:
                    threat_score += 0.1
                    threats.append({
                        "signature_name": pattern,
                        "threat_level": 0.1,
                        "details": f"Suspicious pattern found: {pattern}"
                    })

            threat_score = min(threat_score, 1.0)

            analysis_result = {
                "filename": file_name,  # ✅ for GUI display
                "file_size": file_size,
                "file_extension": file_ext,
                "file_type": file_type,
                "file_hash": sha256_hash,
                "md5_hash": md5_hash,
                "is_executable": is_executable,
                "threat_level": round(threat_score, 2),
                "threat_analysis": {
                    "threats": threats
                }
            }

            self.logger.info(f"File analysis completed for {file_name}, threat level: {threat_score}")
            return analysis_result

        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {
                "error": f"Analysis failed: {str(e)}",
                "filename": os.path.basename(file_path),
                "threat_level": 0.5,
                "threat_analysis": {"threats": []}
            }

    def _calculate_hash(self, file_path, algorithm="sha256"):
        hash_obj = hashlib.md5() if algorithm == "md5" else hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def _is_executable(self, file_path, file_ext):
        platform_name = settings.PLATFORM
        if file_ext in settings.EXECUTABLE_EXTENSIONS.get(platform_name, []):
            return True
        if platform_name in ["Linux", "Darwin"]:
            return os.access(file_path, os.X_OK)
        return False

    def _check_script_for_suspicious_patterns(self, file_path):
        suspicious_found = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            patterns = {
                "Obfuscation": r"eval\(|exec\(|base64\.decode|fromCharCode",
                "System Access": r"subprocess\.call|os\.system|exec\s+|runtime\.exec",
                "Privilege Escalation": r"sudo|runas|powershell -command",
                "Network Connection": r"socket\.connect|http[s]?://|urllib|requests\.get|curl |wget ",
                "Data Exfiltration": r"\.upload\(|POST http|ftp\.put|send\(|mail\(",
                "Registry Access": r"HKEY_|Registry\.|Reg(Create|Set)Key",
                "Browser Exploit": r"navigator\.userAgent|document\.cookie|localStorage|sessionStorage"
            }

            for name, pattern in patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    suspicious_found.append(f"Suspicious {name} pattern")
        except Exception:
            pass

        return suspicious_found
