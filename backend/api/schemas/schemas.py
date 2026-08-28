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
    deleted_at: Optional[datetime] = None
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
    project_id: Optional[str] = None  # null = client-wide (visible to all projects)
    credentials: Dict[str, Any]       # plaintext; encrypted server-side
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
    # Git repo URL + optional PAT for connector-less AI code review scans.
    # repo_url takes precedence over the connector's stored repo_url.
    # git_token is stored encrypted in scan.summary; never returned to the client.
    repo_url: Optional[str] = None
    git_token: Optional[str] = None

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
    progress_message: Optional[str]
    created_at: Optional[datetime]
    parent_scan_id: Optional[str] = None
    is_live: bool = True
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
    # Dedup metadata — populated by the findings list endpoint.
    # seen_count / first_seen_at: legacy read-side dedup (still used for old rows)
    seen_count: Optional[int] = 1
    first_seen_at: Optional[datetime] = None
    # Write-side dedup fields (set at ingest time starting with this release):
    # occurrence_count = how many scans confirmed this finding (canonical only)
    # last_seen_at = most recent scan that found it
    # duplicate_of_id = non-null on marker rows that link to the canonical row
    occurrence_count: Optional[int] = 1
    last_seen_at: Optional[datetime] = None
    duplicate_of_id: Optional[str] = None
    suppressed_at: Optional[datetime] = None
    suppression_reason: Optional[str] = None
    playbook: Optional[str] = None
    acceptance_justification: Optional[str] = None
    accepted_by: Optional[str] = None
    acceptance_expires_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    remediation: Optional[str] = None
    suppression_reason: Optional[str] = None
    acceptance_justification: Optional[str] = None
    accepted_by: Optional[str] = None
    acceptance_expires_at: Optional[datetime] = None


# ── Risk ───────────────────────────────────────────────────────────────────────

class RiskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    risk_level: RiskLevel
    likelihood: int = 5      # 1-10 scale
    impact: int = 5          # 1-10 scale
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
    # GCC IM8 structured assessment fields
    risk_area: Optional[str] = None
    risk_type_gcim8: Optional[str] = None
    accessibility: Optional[int] = None
    discoverability: Optional[int] = None
    exploitability: Optional[int] = None
    authentication_score: Optional[int] = None
    repeatability: Optional[int] = None
    likelihood_avg: Optional[float] = None
    consequence: Optional[int] = None
    # Impact factor breakdown
    data_impact: Optional[int] = None
    operational_impact: Optional[int] = None
    financial_impact: Optional[int] = None
    impact_avg: Optional[float] = None
    risk_matrix_score: Optional[int] = None
    residual_risk_level: Optional[str] = None
    treatment_option: Optional[str] = None
    proposal_id: Optional[str] = None
    wizard_data_json: Optional[str] = None
    measures_json: Optional[str] = None
    ai_assessment_json: Optional[str] = None
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
    scan_id: Optional[str] = None
    input_data: Optional[Dict[str, Any]]
    output_data: Optional[Dict[str, Any]]
    tokens_used: Optional[int]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    hidden_at: Optional[datetime] = None
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
    reappeared_at: Optional[datetime] = None
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


# ── Threat Register ────────────────────────────────────────────────────────────

class ThreatEntryResponse(BaseModel):
    id: str
    client_id: str
    agent_run_id: Optional[str] = None
    scan_id: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    confidence: Optional[str] = None
    finding_id: Optional[str] = None
    severity: Optional[str] = None
    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    framework_references: Optional[List] = []
    sigma_rule: Optional[str] = None
    status: str = "active"
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

class ThreatEntryUpdate(BaseModel):
    status: Optional[str] = None


# ── Control Deficiency Register ─────────────────────────────────────────────────

class ControlDeficiencyResponse(BaseModel):
    id: str
    client_id: str
    agent_run_id: Optional[str] = None
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None
    control_id: Optional[str] = None
    framework: Optional[str] = None
    severity: Optional[str] = None
    title: str
    gap_description: Optional[str] = None
    regulatory_reference: Optional[str] = None
    remediation: Optional[str] = None
    audit_readiness_score: Optional[int] = None
    status: str = "open"
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

class ControlDeficiencyUpdate(BaseModel):
    status: Optional[str] = None


# ── Remediation Action Tracker ──────────────────────────────────────────────────

class RemediationActionResponse(BaseModel):
    id: str
    client_id: str
    agent_run_id: Optional[str] = None
    scan_id: Optional[str] = None
    title: Optional[str] = None
    action: str
    band: Optional[str] = None
    priority: Optional[int] = None
    effort: Optional[str] = None
    impact: Optional[str] = None
    status: str = "open"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

class RemediationActionUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None


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


# ── Posture History ────────────────────────────────────────────────────────────
class PostureSnapshotResponse(BaseModel):
    id: str
    client_id: str
    captured_at: Optional[datetime]
    open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_risks: int
    mttr_critical_hours: Optional[float]
    mttr_high_hours: Optional[float]
    compliance_score: Optional[float]
    scan_count_30d: int
    agent_runs_30d: int
    model_config = {"from_attributes": True}

# ── Comments ───────────────────────────────────────────────────────────────────
class CommentCreate(BaseModel):
    entity_type: str
    entity_id: str
    body: str

class CommentResponse(BaseModel):
    id: str
    client_id: str
    entity_type: str
    entity_id: str
    author_email: str
    author_name: Optional[str]
    body: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    model_config = {"from_attributes": True}

# ── Webhooks ───────────────────────────────────────────────────────────────────
class WebhookCreate(BaseModel):
    name: str
    url: str
    secret: Optional[str] = None
    events: List[str] = []
    client_id: Optional[str] = None

class WebhookResponse(BaseModel):
    id: str
    client_id: Optional[str]
    name: str
    url: str
    events: Optional[List[str]]
    is_active: bool
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}

# ── Scorecard ──────────────────────────────────────────────────────────────────
class ScorecardTokenResponse(BaseModel):
    id: str
    client_id: str
    token: str
    label: str
    is_active: bool
    created_at: Optional[datetime]
    expires_at: Optional[datetime]
    model_config = {"from_attributes": True}

# ── CTEM ───────────────────────────────────────────────────────────────────────
class CTEMPhaseNoteResponse(BaseModel):
    id: str
    program_id: str
    phase: str
    notes: Optional[str]
    actions: Optional[List[str]]
    completed: bool
    completed_at: Optional[datetime]
    completed_by: Optional[str]
    ai_brief: Optional[str] = None
    ai_brief_generated_at: Optional[datetime] = None
    phase_data_json: Optional[Dict[str, Any]] = None
    model_config = {"from_attributes": True}

class CTEMProgramCreate(BaseModel):
    name: str
    description: Optional[str] = None
    connector_ids: List[str] = []

class CTEMProgramResponse(BaseModel):
    id: str
    client_id: str
    name: str
    description: Optional[str]
    status: str
    current_phase: str
    created_by: Optional[str]
    created_at: Optional[datetime]
    phases: List[CTEMPhaseNoteResponse] = []
    connector_ids: List[str] = []
    model_config = {"from_attributes": True}

# ── Security Documents ─────────────────────────────────────────────────────────
class SecurityDocumentResponse(BaseModel):
    id: str
    client_id: str
    filename: str
    content_type: Optional[str]
    size_bytes: int
    chunk_count: int
    uploaded_by: Optional[str]
    uploaded_at: Optional[datetime]
    model_config = {"from_attributes": True}

# ── API Keys ───────────────────────────────────────────────────────────────────
class APIKeyCreate(BaseModel):
    name: str
    client_id: Optional[str] = None
    scopes: List[str] = ["read:findings", "read:risks", "read:dashboard"]
    expires_days: Optional[int] = None  # None = never expires

class APIKeyResponse(BaseModel):
    id: str
    client_id: Optional[str]
    name: str
    key_prefix: str
    scopes: Optional[List[str]]
    is_active: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}

class APIKeyCreated(APIKeyResponse):
    """Returned only at creation time — includes the full key."""
    full_key: str
