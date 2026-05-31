"""
NexGenCyberAI - SQLAlchemy ORM models (all tables).
"""
from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, ForeignKey,
    Enum as SAEnum, JSON, Float, UniqueConstraint
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
    WEB = "web"  # OWASP ZAP target — auth or unauth web/API scanning
    # SAST (Static Application Security Testing)
    SEMGREP = "semgrep"
    CODEQL = "codeql"
    SONARQUBE = "sonarqube"
    # Network & Infrastructure Scanning
    NMAP = "nmap"
    OPENVAS = "openvas"
    TRIVY = "trivy"
    # Dependency & Secret Scanning
    OWASP_DC = "owasp_dc"
    GITLEAKS = "gitleaks"
    TRUFFLEHOG = "trufflehog"


class ScannerCategory(str, enum.Enum):
    """Logical grouping for scanners on the Scans / Connectors UI."""
    DAST = "dast"           # Dynamic Application Security Testing (web ZAP)
    SAST = "sast"           # Static Application Security Testing (semgrep, codeql, sonar)
    NETWORK = "network"     # Network & infra (nmap, openvas, trivy container)
    DEPENDENCY = "dependency"  # Dependency + secret scanning (OWASP DC, gitleaks, trufflehog)
    CLOUD = "cloud"         # Existing cloud / identity connectors


# ConnectorType → ScannerCategory dispatch. New scanners must register here so
# the UI and factory both know which group they belong to.
CONNECTOR_CATEGORY: dict["ConnectorType", "ScannerCategory"] = {
    ConnectorType.WEB: ScannerCategory.DAST,
    ConnectorType.SEMGREP: ScannerCategory.SAST,
    ConnectorType.CODEQL: ScannerCategory.SAST,
    ConnectorType.SONARQUBE: ScannerCategory.SAST,
    ConnectorType.NMAP: ScannerCategory.NETWORK,
    ConnectorType.OPENVAS: ScannerCategory.NETWORK,
    ConnectorType.TRIVY: ScannerCategory.NETWORK,
    ConnectorType.OWASP_DC: ScannerCategory.DEPENDENCY,
    ConnectorType.GITLEAKS: ScannerCategory.DEPENDENCY,
    ConnectorType.TRUFFLEHOG: ScannerCategory.DEPENDENCY,
}

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
    # CIS Benchmarks — cloud/SaaS (full catalog ships)
    CIS_AZURE = "cis_azure"
    CIS_AWS = "cis_aws"
    CIS_AWS_DB = "cis_aws_db"
    CIS_ALIBABA = "cis_alibaba"
    CIS_GCP = "cis_gcp"
    CIS_GCP_WORKSPACE = "cis_gcp_workspace"
    CIS_M365 = "cis_m365"
    CIS_AKS = "cis_aks"
    CIS_AZURE_COMPUTE = "cis_azure_compute"
    # CIS Benchmarks — OS/network/app (section structure ships; full controls via /import)
    CIS_WINDOWS_SERVER = "cis_windows_server"
    CIS_UBUNTU = "cis_ubuntu"
    CIS_ESXI = "cis_esxi"
    CIS_F5 = "cis_f5"
    CIS_PALO_ALTO = "cis_palo_alto"
    CIS_MSSQL = "cis_mssql"
    # ZAP — DAST baselines. Each control == one ZAP plugin rule (control_id "ZAP-<pluginId>").
    ZAP_UNAUTH_PASSIVE = "zap_unauth_passive"   # baseline profile, no auth
    ZAP_AUTH_ACTIVE = "zap_auth_active"         # active profile, with auth

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

class AssetStatus(str, enum.Enum):
    ACTIVE = "active"
    STALE = "stale"
    DELETED = "deleted"

class AccessRole(str, enum.Enum):
    READER = "reader"
    EDITOR = "editor"
    ADMIN = "admin"

class AccessScope(str, enum.Enum):
    GLOBAL = "global"
    CLIENT = "client"
    PROJECT = "project"

class ControlStatus(str, enum.Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


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
    control_statuses = relationship("ClientControlStatus", back_populates="client", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="client", cascade="all, delete-orphan")


class Project(Base):
    """A logical grouping under a Client. Connectors, Scans, and Assets all
    belong to a Project. Existing entities pre-Projects are migrated to a
    "Default" project per client by main.py::_ensure_projects_schema."""
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("client_id", "name", name="uq_project_client_name"),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    environment = Column(String(64))            # production | staging | development | dr | other
    cloud_provider = Column(String(32))         # azure | aws | gcp | multi | other
    metadata_ = Column("metadata", JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    client = relationship("Client", back_populates="projects")
    connectors = relationship("Connector", back_populates="project")
    scans = relationship("Scan", back_populates="project")
    assets = relationship("Asset", back_populates="project")


class Connector(Base):
    __tablename__ = "connectors"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False)
    project_id = Column(String(36), ForeignKey("projects.id"), index=True)  # populated by migration; required for new rows
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
    project = relationship("Project", back_populates="connectors")
    scans = relationship("Scan", back_populates="connector")
    assets = relationship("Asset", back_populates="connector", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False)
    project_id = Column(String(36), ForeignKey("projects.id"), index=True)
    connector_id = Column(String(36), ForeignKey("connectors.id"))
    name = Column(String(200))                 # human-friendly label so AI agents and users can target a specific scan
    scan_type = Column(SAEnum(ScanType, values_callable=_ev), nullable=False)
    status = Column(SAEnum(ScanStatus, values_callable=_ev), default=ScanStatus.PENDING)
    framework = Column(SAEnum(FrameworkType, values_callable=_ev))
    initiated_by = Column(String(200))       # user UPN from Entra ID
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    summary = Column(JSON, default={})       # {total, critical, high, medium, low, passed, failed}
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Structured AI verdict — see services/verdict.py for shape.
    # Generated automatically when a scan flips to COMPLETED, can be
    # regenerated via POST /scans/{id}/generate-verdict.
    ai_verdict = Column(JSON)
    ai_verdict_generated_at = Column(DateTime(timezone=True))
    # When this scan is a rescan, points at the previous run sharing the
    # same connector + scan_type + framework. UI walks the chain to build
    # version history for a target.
    parent_scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)

    client = relationship("Client", back_populates="scans")
    project = relationship("Project", back_populates="scans")
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
    control_mappings = Column(JSON, default={})  # {framework_value: [control_ids]} — fans this finding out across frameworks
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


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("connector_id", "external_id", name="uq_asset_connector_external"),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), index=True)
    connector_id = Column(String(36), ForeignKey("connectors.id"), nullable=False, index=True)
    external_id = Column(String(512), nullable=False)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(128))             # provider-native (e.g. Microsoft.Compute/virtualMachines)
    asset_class = Column(String(64), index=True) # vm | storage | network | database | identity | keyvault | other
    region = Column(String(64))
    subscription_id = Column(String(64))         # Azure
    resource_group = Column(String(128))         # Azure
    account_id = Column(String(64))              # AWS
    cloud_project_id = Column(String(64))        # GCP cloud project ID (renamed from project_id when internal Project FK was introduced)
    tags = Column(JSON, default={})
    provider_metadata = Column(JSON, default={})
    status = Column(SAEnum(AssetStatus, values_callable=_ev), default=AssetStatus.ACTIVE)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_synced_at = Column(DateTime(timezone=True), server_default=func.now())

    connector = relationship("Connector", back_populates="assets")
    project = relationship("Project", back_populates="assets")


class FrameworkControl(Base):
    __tablename__ = "framework_controls"
    __table_args__ = (
        UniqueConstraint("framework", "control_id", name="uq_framework_control"),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    framework = Column(SAEnum(FrameworkType, values_callable=_ev), nullable=False, index=True)
    control_id = Column(String(64), nullable=False, index=True)
    parent_control_id = Column(String(64))
    domain = Column(String(128))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    weight = Column(Integer, default=1)
    metadata_ = Column("metadata", JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    statuses = relationship("ClientControlStatus", back_populates="control", cascade="all, delete-orphan")


class ClientControlStatus(Base):
    __tablename__ = "client_control_statuses"
    __table_args__ = (
        UniqueConstraint("client_id", "framework_control_id", name="uq_client_control"),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False, index=True)
    framework_control_id = Column(String(36), ForeignKey("framework_controls.id"), nullable=False, index=True)
    status = Column(SAEnum(ControlStatus, values_callable=_ev), default=ControlStatus.NOT_APPLICABLE)
    derived = Column(Boolean, default=True)
    evidence = Column(Text)
    derived_finding_ids = Column(JSON, default=[])
    last_evaluated_at = Column(DateTime(timezone=True), server_default=func.now())
    overridden_by = Column(String(200))
    overridden_at = Column(DateTime(timezone=True))

    client = relationship("Client", back_populates="control_statuses")
    control = relationship("FrameworkControl", back_populates="statuses")


class UserAccess(Base):
    """RBAC grant: a user's role at a particular scope.

    A user (identified by Entra ID UPN / email, lowercased) can hold multiple
    grants. Effective role for a resource = max(role) across all grants whose
    scope covers the resource (project scope ⊆ client scope ⊆ global).
    """
    __tablename__ = "user_access"
    __table_args__ = (
        UniqueConstraint("email", "role", "scope_type", "scope_id", name="uq_user_access_grant"),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    email = Column(String(254), nullable=False, index=True)        # case-normalized to lowercase on write
    role = Column(SAEnum(AccessRole, values_callable=_ev), nullable=False, index=True)
    scope_type = Column(SAEnum(AccessScope, values_callable=_ev), nullable=False)
    scope_id = Column(String(36))                                  # NULL for global; clients.id or projects.id otherwise
    granted_by = Column(String(254))                                # UPN of the admin who granted this
    granted_at = Column(DateTime(timezone=True), server_default=func.now())


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


class AISettings(Base):
    """Single-row table holding tenant-wide AI provider configuration. Lets
    admins override env-var keys/endpoints from the UI. API keys are stored
    encrypted via core.encryption.encrypt."""
    __tablename__ = "ai_settings"

    id = Column(String(36), primary_key=True, default=_uuid)
    default_provider = Column(String(64))
    default_model = Column(String(128))
    default_temperature = Column(Float, default=0.1)

    openai_api_key_enc = Column(Text)
    azure_openai_api_key_enc = Column(Text)
    azure_openai_endpoint = Column(String(512))
    azure_openai_deployment = Column(String(128))
    azure_openai_api_version = Column(String(64))
    anthropic_api_key_enc = Column(Text)
    google_api_key_enc = Column(Text)
    aws_bedrock_region = Column(String(64))
    aws_bedrock_access_key_enc = Column(Text)
    aws_bedrock_secret_key_enc = Column(Text)

    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by = Column(String(255))


# ── Scheduled Missions ────────────────────────────────────────────────────────

class MissionType(str, enum.Enum):
    SOC_DESIGN = "soc_design"
    VULNERABILITY_RESPONSE = "vulnerability_response"
    GRC_ADVISORY = "grc_advisory"
    CLOUD_SECURITY_ASSESSMENT = "cloud_security_assessment"
    ZERO_TRUST_DESIGN = "zero_trust_design"
    INCIDENT_RESPONSE_PROGRAM = "incident_response_program"
    THREAT_INTEL_PROGRAM = "threat_intel_program"
    DATA_PROTECTION_ASSESSMENT = "data_protection_assessment"
    IGA_DEPLOYMENT = "iga_deployment"
    PHISHING_TRIAGE = "phishing_triage"
    PORTFOLIO_RATIONALIZATION = "portfolio_rationalization"
    SECURITY_ARCHITECTURE_REVIEW = "security_architecture_review"


class MissionRunStatus(str, enum.Enum):
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScheduledMission(Base):
    """A recurring security mission configured to run on a cron schedule."""
    __tablename__ = "scheduled_missions"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False, default="New Scheduled Mission")
    client_id = Column(String(36), ForeignKey("clients.id"), nullable=False, index=True)
    mission_type = Column(SAEnum(MissionType, values_callable=_ev), nullable=False)
    cron_expression = Column(String(64), nullable=False)
    cron_label = Column(String(255))
    timezone = Column(String(64), default="UTC")
    # Post-run actions
    send_summary_email = Column(Boolean, default=False)
    update_risk_quantification = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_run_at = Column(DateTime(timezone=True))
    next_run_at = Column(DateTime(timezone=True))

    client = relationship("Client")
    runs = relationship("ScheduledMissionRun", back_populates="mission", cascade="all, delete-orphan")


class ScheduledMissionRun(Base):
    """Audit log row for each execution of a scheduled mission."""
    __tablename__ = "scheduled_mission_runs"

    id = Column(String(36), primary_key=True, default=_uuid)
    mission_id = Column(String(36), ForeignKey("scheduled_missions.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(SAEnum(MissionRunStatus, values_callable=_ev), nullable=False)
    triggered_by = Column(String(32), default="scheduler")  # "scheduler" | "manual" | "system"
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    output = Column(Text)
    error = Column(Text)
    # Structured LLM-generated report. Same fixed schema for every run so
    # the UI renders identically. See services/mission_reports.py.
    report = Column(JSON)

    mission = relationship("ScheduledMission", back_populates="runs")


# ── Knowledge Base ────────────────────────────────────────────────────────────

class KnowledgeFile(Base):
    """A structured security knowledge file consumed by AI specialist agents.

    Files are organized by category (e.g. "frameworks_and_standards") and
    contain nested sections (Disclaimer, Frameworks, Regulatory Deadlines, …).
    Each file tracks which agents reference it so the dashboard can show
    "X knowledge files powering Y specialist agents".
    """
    __tablename__ = "knowledge_files"

    id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    description = Column(Text)
    version = Column(String(32), default="v1.0")
    size_kb = Column(Integer, default=0)
    # JSON list of agent identifiers (string IDs/types) that consume this file
    used_by = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    sections = relationship("KnowledgeFileSection", back_populates="file",
                            cascade="all, delete-orphan", order_by="KnowledgeFileSection.position")


class AIAgent(Base):
    """A configurable AI specialist agent in the catalog.

    Each row defines an agent's identity, group, and LLM configuration.
    Built-in agents (`is_builtin=True`) are seeded on startup and cannot
    be deleted by non-admins. Custom agents are added via the admin UI.

    Note: legacy operational agents from `AgentType` enum (risk_manager,
    va_scanner, etc.) also live in this table with `key` matching the
    enum value, so the Agents page can render one unified grouped list.
    Their `legacy_orchestrator=True` flag tells the UI to use the
    existing `/clients/{client_id}/agents/run/` execution path.
    """
    __tablename__ = "ai_agents"

    id = Column(String(36), primary_key=True, default=_uuid)
    key = Column(String(128), nullable=False, unique=True, index=True)  # slug
    name = Column(String(255), nullable=False)
    group_key = Column(String(64), nullable=False, index=True)
    group_label = Column(String(128), nullable=False)
    description = Column(Text)
    objective = Column(Text)
    domain = Column(String(255))
    system_prompt = Column(Text)
    # LLM overrides — null means inherit from AISettings/env defaults
    provider = Column(String(64))
    model = Column(String(128))
    temperature = Column(Float, default=0.1)
    max_tokens = Column(Integer, default=4096)
    # JSON list of tool identifiers + knowledge file IDs
    tools_enabled = Column(JSON, default=list)
    knowledge_file_ids = Column(JSON, default=list)
    # Flags
    is_builtin = Column(Boolean, default=False, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    legacy_orchestrator = Column(Boolean, default=False, nullable=False)
    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    updated_by = Column(String(255))


class KnowledgeFileSection(Base):
    """One section inside a KnowledgeFile.

    Section types observed: disclaimer (char count), frameworks (list of names),
    regulatory_deadlines (list), capability_matrix (key→count map), applicability
    (key list), cross_mapping (key list), industry_benchmarks (key list).
    """
    __tablename__ = "knowledge_file_sections"

    id = Column(String(36), primary_key=True, default=_uuid)
    file_id = Column(String(36), ForeignKey("knowledge_files.id", ondelete="CASCADE"), nullable=False, index=True)
    position = Column(Integer, default=0)
    name = Column(String(255), nullable=False)
    section_type = Column(String(64), nullable=False)  # disclaimer | frameworks | items | matrix | applicability
    # Free-form section body. For list sections: {"items": [...]}; for matrix
    # sections: {"keys": {"key": count, ...}}; for disclaimer: {"chars": N, "text": "..."}
    body = Column(JSON, default={})

    file = relationship("KnowledgeFile", back_populates="sections")
