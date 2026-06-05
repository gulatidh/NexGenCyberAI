"""
NexGenCyberAI - Pydantic v2 request/response schemas.
"""
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from api.models.models import (
    ConnectorType, ConnectorStatus, FrameworkType, ScanType,
    ScanStatus, Severity, RiskLevel, AgentType, AssetStatus, ControlStatus,
    AccessRole, AccessScope,
)


# ── Client ─────────────────────────────────────────────────────────────────────

class ClientCreate(BaseModel):
    name: str
    slug: str
    industry: Optional[str] = None
    country: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    logo_url: Optional[str] = None
    metadata_: Optional[Dict[str, Any]] = {}

class ClientUpdate(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    country: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    logo_url: Optional[str] = None
    is_active: Optional[bool] = None
    metadata_: Optional[Dict[str, Any]] = None

class ClientResponse(BaseModel):
    id: str
    name: str
    slug: str
    industry: Optional[str]
    country: Optional[str]
    contact_name: Optional[str]
    contact_email: Optional[str]
    logo_url: Optional[str]
    is_active: bool
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ── Project ────────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    environment: Optional[str] = None
    cloud_provider: Optional[str] = None
    metadata_: Optional[Dict[str, Any]] = {}

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[str] = None
    cloud_provider: Optional[str] = None
    metadata_: Optional[Dict[str, Any]] = None

class ProjectResponse(BaseModel):
    id: str
    client_id: str
    name: str
    description: Optional[str]
    environment: Optional[str]
    cloud_provider: Optional[str]
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ── Connector ──────────────────────────────────────────────────────────────────

class ConnectorCreate(BaseModel):
    name: str
    connector_type: ConnectorType
    project_id: str                 # required — connectors must belong to a project
    credentials: Dict[str, Any]     # plaintext; encrypted server-side
    config: Optional[Dict[str, Any]] = {}

class ConnectorUpdate(BaseModel):
    name: Optional[str] = None
    project_id: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    status: Optional[ConnectorStatus] = None

class ConnectorResponse(BaseModel):
    id: str
    client_id: str
    project_id: Optional[str]
    name: str
    connector_type: ConnectorType
    status: ConnectorStatus
    config: Optional[Dict[str, Any]]
    last_synced_at: Optional[datetime]
    error_message: Optional[str]
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ── Scan ───────────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    connector_id: Optional[str] = None
    project_id: Optional[str] = None     # inferred from connector if omitted
    name: Optional[str] = None            # human-friendly label
    scan_type: ScanType
    framework: Optional[FrameworkType] = None
    # Optional list of catalog control_ids to scope the scan to. When set, the
    # connector still runs full discovery but persisted findings are filtered to
    # those whose control_mappings[framework] (or normalized control_id) intersects.
    control_ids: Optional[List[str]] = None
    # If true, the scan is created in PENDING but no _execute_scan task is
    # queued — caller must follow up with another call (e.g. upload-binary)
    # that fires the workflow once the prerequisite is ready.
    defer_dispatch: Optional[bool] = False

class ScanResponse(BaseModel):
    id: str
    client_id: str
    project_id: Optional[str]
    connector_id: Optional[str]
    name: Optional[str]
    scan_type: ScanType
    status: ScanStatus
    framework: Optional[FrameworkType]
    initiated_by: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    summary: Optional[Dict[str, Any]]
    error_message: Optional[str]
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ── Finding ────────────────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    description: Optional[str]
    severity: Severity
    resource_id: Optional[str]
    resource_type: Optional[str]
    control_id: Optional[str]
    framework: Optional[FrameworkType]
    status: str
    remediation: Optional[str]
    cve_id: Optional[str]
    cvss_score: Optional[float]
    created_at: Optional[datetime]
    # Dedupe metadata: when the same (resource_id, title) appears in multiple
    # scans, the listing collapses them to a single row. seen_count = number
    # of scans that flagged it; first_seen_at = earliest detection.
    seen_count: Optional[int] = 1
    first_seen_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    remediation: Optional[str] = None


# ── Risk ───────────────────────────────────────────────────────────────────────

class RiskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    risk_level: RiskLevel
    likelihood: int = 3
    impact: int = 3
    category: Optional[str] = None
    owner: Optional[str] = None
    due_date: Optional[datetime] = None
    mitigation_plan: Optional[str] = None
    finding_ids: Optional[List[str]] = []

class RiskResponse(BaseModel):
    id: str
    client_id: str
    title: str
    description: Optional[str]
    risk_level: RiskLevel
    likelihood: int
    impact: int
    risk_score: Optional[float]
    category: Optional[str]
    owner: Optional[str]
    due_date: Optional[datetime]
    status: str
    mitigation_plan: Optional[str]
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ── Framework Assessment ───────────────────────────────────────────────────────

class FrameworkAssessmentResponse(BaseModel):
    id: str
    client_id: str
    framework: FrameworkType
    overall_score: Optional[float]
    controls_total: int
    controls_passed: int
    controls_failed: int
    controls_partial: int
    control_results: Optional[Dict[str, Any]]
    assessed_at: Optional[datetime]
    model_config = {"from_attributes": True}


# ── Agent ──────────────────────────────────────────────────────────────────────

class AgentRunRequest(BaseModel):
    agent_type: AgentType
    scan_id: Optional[str] = None
    input_data: Optional[Dict[str, Any]] = {}

class AgentRunResponse(BaseModel):
    id: str
    client_id: Optional[str]
    agent_type: AgentType
    status: str
    input_data: Optional[Dict[str, Any]]
    output_data: Optional[Dict[str, Any]]
    tokens_used: Optional[int]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    model_config = {"from_attributes": True}


# ── Asset Inventory ────────────────────────────────────────────────────────────

class AssetResponse(BaseModel):
    id: str
    client_id: str
    project_id: Optional[str]
    connector_id: str
    external_id: str
    name: str
    asset_type: Optional[str]
    asset_class: Optional[str]
    region: Optional[str]
    subscription_id: Optional[str]
    resource_group: Optional[str]
    account_id: Optional[str]
    project_id: Optional[str]
    tags: Optional[Dict[str, Any]] = {}
    status: AssetStatus
    first_seen_at: Optional[datetime]
    last_synced_at: Optional[datetime]
    open_findings_count: int = 0
    risks_count: int = 0
    model_config = {"from_attributes": True}

class AssetDetailResponse(AssetResponse):
    provider_metadata: Optional[Dict[str, Any]] = {}
    findings: List[FindingResponse] = []
    risks: List[RiskResponse] = []

class AssetSyncResponse(BaseModel):
    queued_connector_ids: List[str]
    message: str


# ── Framework Compliance ───────────────────────────────────────────────────────

class FrameworkControlResponse(BaseModel):
    id: str
    framework: FrameworkType
    control_id: str
    parent_control_id: Optional[str]
    domain: Optional[str]
    title: str
    description: Optional[str]
    weight: int = 1
    model_config = {"from_attributes": True}

class ControlStatusResponse(BaseModel):
    control: FrameworkControlResponse
    status: ControlStatus
    derived: bool
    evidence: Optional[str]
    last_evaluated_at: Optional[datetime]
    overridden_by: Optional[str]
    overridden_at: Optional[datetime]
    finding_ids: List[str] = []

class ControlStatusUpdate(BaseModel):
    status: ControlStatus
    evidence: Optional[str] = None

class FrameworkSummaryResponse(BaseModel):
    framework: FrameworkType
    total: int
    compliant: int
    non_compliant: int
    partial: int
    not_applicable: int
    score: float
    last_evaluated_at: Optional[datetime] = None

class FrameworkCatalogEntry(BaseModel):
    framework: FrameworkType
    name: str
    version: Optional[str] = None
    total_controls: int


# ── RBAC ───────────────────────────────────────────────────────────────────────

class GrantCreate(BaseModel):
    email: str
    role: AccessRole
    scope_type: AccessScope
    scope_id: Optional[str] = None      # required when scope_type != global

class GrantResponse(BaseModel):
    id: str
    email: str
    role: AccessRole
    scope_type: AccessScope
    scope_id: Optional[str]
    scope_label: Optional[str] = None    # human-friendly: "Greta — Production" etc.
    granted_by: Optional[str]
    granted_at: Optional[datetime]
    model_config = {"from_attributes": True}

class UserAccessSummary(BaseModel):
    email: str
    grants: List[GrantResponse] = []
    effective_global_role: Optional[AccessRole] = None

class MyAccessResponse(BaseModel):
    email: str
    grants: List[GrantResponse] = []
    is_admin: bool                          # global admin
    is_admin_anywhere: bool = False         # admin at any scope (for nav gating)
    is_editor_anywhere: bool
    manageable_scopes: Dict[str, Any] = {}  # {global, client_ids[], project_ids[]}


# ── Misc ───────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    db: str

class DashboardSummary(BaseModel):
    total_clients: int
    active_connectors: int
    open_findings: int
    critical_findings: int
    findings_by_severity: Dict[str, int] = {}
    risks_open: int
    scans_last_30d: int
    compliance_scores: Dict[str, float]
    posture_health: Dict[str, float] = {}
    recent_scans: List[Dict] = []
    recent_risks: List[Dict] = []
    recent_findings: List[Dict] = []
    agent_runs_total: int = 0
