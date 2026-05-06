"""
NexGenCyberAI - Abstract base class for all connectors.
Every cloud / SaaS connector must implement this interface.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from dataclasses import dataclass, field
from enum import Enum


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ConnectorFinding:
    title: str
    description: str
    severity: FindingSeverity
    resource_id: str = ""
    resource_type: str = ""
    control_id: str = ""
    framework: str = ""
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cve_id: str = ""
    cvss_score: float = 0.0


@dataclass
class ConnectorTestResult:
    success: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


class BaseConnector(ABC):
    """All connectors must inherit this and implement all abstract methods."""

    def __init__(self, credentials: Dict[str, Any], config: Dict[str, Any]):
        self.credentials = credentials
        self.config = config

    @abstractmethod
    async def test_connection(self) -> ConnectorTestResult:
        """Verify credentials and connectivity."""
        ...

    @abstractmethod
    async def get_resources(self) -> List[Dict[str, Any]]:
        """Return a list of discovered resources (VMs, buckets, etc.)."""
        ...

    @abstractmethod
    async def run_configuration_review(self) -> List[ConnectorFinding]:
        """Evaluate resources against security best practices."""
        ...

    @abstractmethod
    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        """Return vulnerability findings from the platform's native scanner."""
        ...

    @abstractmethod
    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        """Return control-level compliance data for the given framework."""
        ...
