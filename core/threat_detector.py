import os
import json
import platform
from enum import Enum
from typing import List, Dict, Any, Optional
from saferun.core.isolation import get_isolation_environment


class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, level_str: str) -> 'ThreatLevel':
        return {
            "none": cls.NONE,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL
        }.get(level_str.lower(), cls.NONE)


class ThreatSignature:
    def __init__(self, id: str, name: str, description: str, indicators: List[str],
                 severity: ThreatLevel, category: str, platforms: List[str]):
        self.id = id
        self.name = name
        self.description = description
        self.indicators = indicators
        self.severity = severity if isinstance(severity, ThreatLevel) else ThreatLevel.from_string(severity)
        self.category = category
        self.platforms = platforms

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatSignature':
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            indicators=data["indicators"],
            severity=data["severity"],
            category=data["category"],
            platforms=data["platforms"]
        )


class ThreatDetector:
    def __init__(self, security_level: str = "medium", isolation_method: Optional[str] = None):
        self.signatures: List[ThreatSignature] = []
        self.security_level = security_level
        self.isolation_method = isolation_method or "container"
        self.isolation_env = get_isolation_environment(self.isolation_method, self.security_level)

        self.detection_sensitivity = {
            "low": 0.3,
            "medium": 0.5,
            "high": 0.7
        }.get(security_level.lower(), 0.5)

        self._load_signatures()

    def _load_signatures(self):
        self.signatures.extend([
            ThreatSignature(
                id="SIG-001",
                name="System File Access",
                description="Accesses sensitive system files",
                indicators=["/etc/passwd", "C:\\Windows\\System32\\config"],
                severity=ThreatLevel.HIGH,
                category="File Access",
                platforms=["linux", "windows", "macos"]
            ),
            ThreatSignature(
                id="SIG-002",
                name="Registry Modification",
                description="Modifies autorun registry keys",
                indicators=["HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                severity=ThreatLevel.MEDIUM,
                category="Registry Modification",
                platforms=["windows"]
            ),
            ThreatSignature(
                id="SIG-003",
                name="Suspicious Network Connection",
                description="Connects to common malicious ports or domains",
                indicators=[":4444", ":1337", ":31337", ":8080", "malicious.example.com"],
                severity=ThreatLevel.HIGH,
                category="Network Activity",
                platforms=["all"]
            )
        ])

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        score = 0.0
        threats = []
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        if ext in {".exe", ".dll", ".bat", ".ps1"}:
            score += 0.2
            threats.append({"type": "extension", "details": ext, "confidence": 0.8})
        elif ext in {".py", ".js", ".vba"}:
            score += 0.1
            threats.append({"type": "script", "details": ext, "confidence": 0.6})

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            keywords = [
                (b"cmd.exe", ThreatLevel.MEDIUM),
                (b"powershell", ThreatLevel.MEDIUM),
                (b"CreateProcess", ThreatLevel.HIGH),
                (b"WriteProcessMemory", ThreatLevel.HIGH),
                (b"curl", ThreatLevel.LOW),
                (b"wget", ThreatLevel.LOW),
                (b"socket", ThreatLevel.MEDIUM),
                (b"registry", ThreatLevel.MEDIUM),
                (b"os.system", ThreatLevel.MEDIUM),
                (b"eval", ThreatLevel.HIGH),
                (b"exec", ThreatLevel.HIGH),
                (b"malicious.example.com", ThreatLevel.HIGH)
            ]

            for kw, level in keywords:
                if kw in content:
                    weight = {
                        ThreatLevel.CRITICAL: 1.0,
                        ThreatLevel.HIGH: 0.4,
                        ThreatLevel.MEDIUM: 0.2,
                        ThreatLevel.LOW: 0.1
                    }.get(level, 0.1)
                    score += weight
                    threats.append({"type": "keyword", "details": kw.decode(errors='ignore'), "level": level.name})

        except Exception as e:
            threats.append({"type": "error", "details": str(e), "confidence": 0.1})

        return {
            "threat_score": min(score, 1.0),
            "threats": threats
        }

    def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        threat_score = 0.0
        threats = []

        report = report or {}
        file_ops = report.get("file_operations", [])
        network_ops = report.get("network_activity", [])
        registry_ops = report.get("registry_operations", [])

        all_entries = file_ops + network_ops + registry_ops

        for entry in all_entries:
            data_str = json.dumps(entry).lower()
            for sig in self.signatures:
                if platform.system().lower() not in [p.lower() for p in sig.platforms] and "all" not in sig.platforms:
                    continue
                for indicator in sig.indicators:
                    if indicator.lower() in data_str:
                        threat_score += {
                            ThreatLevel.CRITICAL: 1.0,
                            ThreatLevel.HIGH: 0.4,
                            ThreatLevel.MEDIUM: 0.2,
                            ThreatLevel.LOW: 0.1
                        }.get(sig.severity, 0.1)
                        threats.append({
                            "signature_id": sig.id,
                            "signature_name": sig.name,
                            "threat_level": sig.severity.name,
                            "category": sig.category,
                            "details": indicator
                        })
                        break

        result = {
            "threat_score": min(threat_score, 1.0),
            "threats": threats
        }

        # ✅ ADDED: Console output for analysis section
        print("\n[Analysis Report Output]")
        print(json.dumps(result, indent=2))

        return result

