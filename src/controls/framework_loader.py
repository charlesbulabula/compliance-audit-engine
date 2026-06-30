"""
Loads compliance framework control definitions from YAML.
Supports CIS AWS 1.5, SOC2 CC, PCI-DSS 4.0.
"""
from __future__ import annotations
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Control:
    id: str
    title: str
    description: str
    severity: Severity
    automated: bool
    remediation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class FrameworkLoader:
    FRAMEWORKS_DIR = Path(__file__).parent.parent.parent / "config" / "frameworks"
    SUPPORTED = {"CIS_AWS_1_5", "SOC2_CC", "PCI_DSS_4"}

    def __init__(self) -> None:
        self._cache: dict[str, dict[str, Control]] = {}

    def load(self, framework_name: str) -> dict[str, Control]:
        if framework_name not in self.SUPPORTED:
            raise ValueError(f"Unsupported framework: {framework_name}. Choose from {self.SUPPORTED}")
        if framework_name in self._cache:
            return self._cache[framework_name]
        path = self.FRAMEWORKS_DIR / f"{framework_name.lower()}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Framework file not found: {path}")
        with open(path) as f:
            raw = yaml.safe_load(f)
        controls = {}
        for entry in raw.get("controls", []):
            c = Control(
                id=entry["id"],
                title=entry["title"],
                description=entry.get("description", ""),
                severity=Severity(entry.get("severity", "MEDIUM")),
                automated=entry.get("automated", False),
                remediation_steps=entry.get("remediation_steps", []),
                references=entry.get("references", []),
                tags=entry.get("tags", []),
            )
            controls[c.id] = c
        self._cache[framework_name] = controls
        return controls

    def get_control(self, framework_name: str, control_id: str) -> Optional[Control]:
        controls = self.load(framework_name)
        return controls.get(control_id)

    def list_controls(
        self,
        framework_name: str,
        severity: Optional[Severity] = None,
        automated_only: bool = False,
    ) -> list[Control]:
        controls = self.load(framework_name)
        result = list(controls.values())
        if severity:
            result = [c for c in result if c.severity == severity]
        if automated_only:
            result = [c for c in result if c.automated]
        return sorted(result, key=lambda c: (c.severity.value, c.id))

    def list_all_frameworks(self) -> list[str]:
        return [p.stem.upper() for p in self.FRAMEWORKS_DIR.glob("*.yaml")]

    def get_controls_by_tag(self, framework_name: str, tag: str) -> list[Control]:
        return [c for c in self.load(framework_name).values() if tag in c.tags]

# _r 20260630093513-e5a250a9
