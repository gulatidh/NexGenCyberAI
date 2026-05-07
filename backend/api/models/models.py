"""
NexGenCyberAI - SQLAlchemy ORM models (all tables).
"""
from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, ForeignKey,
    Enum as SAEnum, JSON, Float
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from db.database import Base
import enum
import uuid


def _uuid():
    return str(uuid.uuid4())


# Force SQLAlchemy to store enum VALUES (lowercase strings) instead of member names
def _ev(e):
    return [m.value for m in e]


# ── Enums ──────────────────────────────────────────────────────────────────────

class ConnectorType(str, enum.Enum):
    AZURE = "azure"
    AWS = "aws"
    GCP = "gcp"
    ONPREM = "onprem"
    SERVICENOW = "servicenow"
    OKTA = "okta"
    ENTRAID = "entraid"
    CONTAINERS = "containers"
    GITHUB = "github"
    JIRA = "jira"

class ConnectorStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class FrameworkType(str, enum.Enum):
    NIST_CSF = "nist_csf"
    NIST_800_53 = "nist_800_53"
    CIS_V8 = "cis_v8"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"

class ScanType(str, enum.Enum):
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    COMPLIANCE = "compliance"
    FULL = "full"

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class AgentType(str, enum.Enum):
    RISK_MANAGER = "risk_manager"
    VA_SCANNER = "va_scanner"
    FRAMEWORK_ANALYST = "framework_analyst"
    COMPLIANCE_MONITOR = "compliance_monitor"
    THREAT_INTEL = "threat_intel"
    REMEDIATION = "remediation"
    ORCHESTRATOR = "orchestrator"


# ── Tables ─────────────────────────────────────────────────────────────────────

class Client(Base):
    __tablename__ = "clients"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(200), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    industry = Column(String(100))
    country = Column(String(100))
    contact_name = Column(String(200))
    contact_email = Column(String(200))
    logo_url = Column(String(500))
    is_active = Column(Boolean, default=True)
    metadata_ = Column("metadata", JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    connectors = relationship("Connector", back_populates="client", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="client", cascade="all, delete-orphan")
    risks = relationship("Risk", back_populates="client", cascade="all, delete-orphan")
    framework_assessments = relationship("FrameworkAssessment", back_populates="client")


class Connector(Base):
    __tablename__ = "connectors"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False)
    name = Column(String(200), nullable=False)
    connector_type = Column(SAEnum(ConnectorType, values_callable=_ev), nullable=False)
    status = Column(SAEnum(ConnectorStatus, values_callable=_ev), default=ConnectorStatus.PENDING)
    credentials_enc = Column(Text)          # AES-encrypted JSON blob
    config = Column(JSON, default={})       # non-secret config (region, project_id, etc.)
    last_synced_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    client = relationship("Client", back_populates="connectors")
    scans = relationship("Scan", back_populates="connector")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False)
    connector_id = Column(String(36), ForeignKey("connectors.id"))
    scan_type = Column(SAEnum(ScanType, values_callable=_ev), nullable=False)
    status = Column(SAEnum(ScanStatus, values_callable=_ev), default=ScanStatus.PENDING)
    framework = Column(SAEnum(FrameworkType, values_callable=_ev))
    initiated_by = Column(String(200))       # user UPN from Entra ID
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    summary = Column(JSON, default={})       # {total, critical, high, medium, low, passed, failed}
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    client = relationship("Client", back_populates="scans")
    connector = relationship("Connector", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SAEnum(Severity, values_callable=_ev), nullable=False)
    resource_id = Column(String(500))
    resource_type = Column(String(200))
    control_id = Column(String(100))        # CIS 1.1, NIST AC-2, GDPR Art.32, etc.
    framework = Column(SAEnum(FrameworkType, values_callable=_ev))
    status = Column(String(50), default="open")   # open | accepted | remediated | false_positive
    remediation = Column(Text)
    evidence = Column(JSON, default={})
    cve_id = Column(String(50))
    cvss_score = Column(Float)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    scan = relationship("Scan", back_populates="findings")


class Risk(Base):
    __tablename__ = "risks"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    risk_level = Column(SAEnum(RiskLevel, values_callable=_ev), nullable=False)
    likelihood = Column(Integer, default=3)     # 1-5
    impact = Column(Integer, default=3)         # 1-5
    risk_score = Column(Float)
    category = Column(String(100))
    owner = Column(String(200))
    due_date = Column(DateTime(timezone=True))
    status = Column(String(50), default="open")
    mitigation_plan = Column(Text)
    finding_ids = Column(JSON, default=[])
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    client = relationship("Client", back_populates="risks")


class FrameworkAssessment(Base):
    __tablename__ = "framework_assessments"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False)
    framework = Column(SAEnum(FrameworkType, values_callable=_ev), nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.id"))
    overall_score = Column(Float)           # 0-100
    controls_total = Column(Integer, default=0)
    controls_passed = Column(Integer, default=0)
    controls_failed = Column(Integer, default=0)
    controls_partial = Column(Integer, default=0)
    control_results = Column(JSON, default={})
    assessed_at = Column(DateTime(timezone=True), server_default=func.now())

    client = relationship("Client", back_populates="framework_assessments")


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"))
    agent_type = Column(SAEnum(AgentType, values_callable=_ev), nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.id"))
    status = Column(String(50), default="running")
    input_data = Column(JSON, default={})
    output_data = Column(JSON, default={})
    tokens_used = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
