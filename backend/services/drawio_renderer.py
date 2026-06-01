"""draw.io / diagrams.net renderer for threat models.

Takes the structured `components` + `data_flows` JSON that
`services/threat_modeler.py` already emits, and produces valid mxGraph
XML (the native `.drawio` format). The customer can:

  - View it inline via the embedded diagrams.net viewer in the portal
  - Download the .drawio file and edit it in draw.io desktop or web

Layout strategy: swimlanes by trust_zone, fixed canonical column order
(public → dmz → private → data-tier → management → other). Components
stack vertically within their swimlane. Edges (data flows) drawn with
the protocol as label and an unencrypted-warning style if `encrypted`
is false.

Pure stdlib — no dagre, no graphviz, no extra deps. The math is simple
enough that deterministic positions beat black-box layout for a
< 15-component diagram.
"""
from __future__ import annotations
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.sax.saxutils import escape


# Canonical column order — trust zones not in this list fall into "other"
_ZONE_ORDER = ["public", "dmz", "private", "data-tier", "management", "other"]
_ZONE_LABEL = {
    "public": "PUBLIC (Internet)",
    "dmz": "DMZ",
    "private": "PRIVATE",
    "data-tier": "DATA TIER",
    "management": "MANAGEMENT",
    "other": "OTHER",
}

# Geometry constants (px)
_SWIMLANE_WIDTH = 260
_SWIMLANE_GAP = 40
_SWIMLANE_PAD_X = 40
_SWIMLANE_PAD_Y = 40
_SWIMLANE_TITLE_H = 30
_COMP_WIDTH = 220
_COMP_HEIGHT = 60
_COMP_PAD_Y = 24
_COMP_INSET_X = 20

# Component-type → mxGraph style. Defaults to a rounded rectangle; richer
# stencils used for the common types so the diagram doesn't look like a
# wall of identical boxes. Phase 9C — provider-aware keys map directly to
# native draw.io AWS / Azure / GCP / generic stencils so the output looks
# like an actual architecture diagram.
_TYPE_STYLE = {
    # Generic types (kept for back-compat)
    "database": (
        "shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;"
        "size=15;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    ),
    "storage": (
        "shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;"
        "size=15;fillColor=#d5e8d4;strokeColor=#82b366;"
    ),
    "queue": (
        "shape=mscae/queue;html=1;labelPosition=right;align=left;verticalAlign=middle;"
        "spacingLeft=8;fillColor=#fff2cc;strokeColor=#d6b656;"
    ),
    "api": (
        "rounded=1;whiteSpace=wrap;html=1;arcSize=20;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    ),
    "endpoint": (
        "shape=cloud;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;"
    ),
    "vm": (
        "rounded=0;whiteSpace=wrap;html=1;shadow=1;fillColor=#e1d5e7;strokeColor=#9673a6;"
    ),
    "identity": (
        "shape=mxgraph.cisco_safe.actors.user;html=1;labelPosition=right;align=left;"
        "verticalAlign=middle;spacingLeft=8;fillColor=#f5f5f5;strokeColor=#666666;"
    ),
    "secret-store": (
        "shape=mxgraph.security.lock;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
    ),
    "repo": (
        "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;arcSize=10;"
    ),
    # ── AWS stencils ───────────────────────────────────────────────────
    "aws_s3":           "sketch=0;points=[[0,0,0],[0.25,0,0],[0.5,0,0],[0.75,0,0],[1,0,0],[1,0.25,0],[1,0.5,0],[1,0.75,0],[1,1,0],[0.75,1,0],[0.5,1,0],[0.25,1,0],[0,1,0],[0,0.75,0],[0,0.5,0],[0,0.25,0]];outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#E7157B;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.s3;",
    "aws_lambda":       "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#D45B07;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.lambda;",
    "aws_rds":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#3334B9;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.rds;",
    "aws_dynamodb":     "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#3334B9;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.dynamodb;",
    "aws_ec2":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#D45B07;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.ec2;",
    "aws_eks":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#D45B07;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elastic_kubernetes_service;",
    "aws_iam":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#DD344C;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.identity_and_access_management_iam;",
    "aws_apigateway":   "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#E7157B;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.api_gateway;",
    "aws_cognito":      "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#DD344C;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.cognito;",
    "aws_sqs":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#E7157B;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.simple_queue_service;",
    "aws_secretsmanager":"sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#DD344C;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.secrets_manager;",
    # ── Azure stencils ─────────────────────────────────────────────────
    "azure_appservice": "sketch=0;points=[[0,0,0],[0.25,0,0],[0.5,0,0],[0.75,0,0],[1,0,0],[1,0.25,0],[1,0.5,0],[1,0.75,0],[1,1,0],[0.75,1,0],[0.5,1,0],[0.25,1,0],[0,1,0],[0,0.75,0],[0,0.5,0],[0,0.25,0]];outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.app_services;",
    "azure_functions":  "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.function_apps;",
    "azure_sql":        "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.sql_database;",
    "azure_cosmos":     "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.cosmos_db;",
    "azure_storage":    "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.storage_accounts;",
    "azure_keyvault":   "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.key_vaults;",
    "azure_vm":         "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.virtual_machine;",
    "azure_aks":        "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.kubernetes_services;",
    "azure_apim":       "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.api_management_services;",
    "azure_servicebus": "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.service_bus;",
    "entra_id":         "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0078D4;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.azure2.azure_active_directory;",
    # ── GCP stencils ───────────────────────────────────────────────────
    "gcp_storage":      "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#4284F3;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.gcp2.cloud_storage;",
    "gcp_sql":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#4284F3;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.gcp2.cloud_sql;",
    "gcp_gke":          "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#4284F3;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;shape=mxgraph.gcp2.kubernetes_engine;",
    # ── Datastore + identity generic ──────────────────────────────────
    "postgres":         "shape=mxgraph.networking.postgresql;html=1;fillColor=#336791;strokeColor=#ffffff;fontColor=#ffffff;",
    "mongodb":          "shape=mxgraph.networking.mongodb;html=1;fillColor=#13aa52;strokeColor=#ffffff;fontColor=#ffffff;",
    "redis":            "shape=mxgraph.networking.redis;html=1;fillColor=#dc382c;strokeColor=#ffffff;fontColor=#ffffff;",
    "kafka":            "shape=mxgraph.networking.kafka;html=1;fillColor=#231f20;strokeColor=#ffffff;fontColor=#ffffff;",
}


# Aliases / hints from common asset_type or connector_type strings to the
# canonical _TYPE_STYLE keys above. Order matters — first match wins.
_TYPE_HINTS = [
    # AWS
    ("aws s3", "aws_s3"), ("s3 bucket", "aws_s3"), ("s3", "aws_s3"),
    ("aws lambda", "aws_lambda"), ("lambda", "aws_lambda"),
    ("aws rds", "aws_rds"), ("rds", "aws_rds"),
    ("dynamodb", "aws_dynamodb"),
    ("aws ec2", "aws_ec2"), ("ec2", "aws_ec2"),
    ("eks", "aws_eks"),
    ("aws iam", "aws_iam"), ("iam role", "aws_iam"),
    ("api gateway", "aws_apigateway"), ("apigw", "aws_apigateway"),
    ("cognito", "aws_cognito"),
    ("sqs", "aws_sqs"),
    ("secrets manager", "aws_secretsmanager"), ("aws secret", "aws_secretsmanager"),
    # Azure
    ("app service", "azure_appservice"), ("appsvc", "azure_appservice"), ("azure app", "azure_appservice"),
    ("function app", "azure_functions"), ("azure function", "azure_functions"),
    ("azure sql", "azure_sql"), ("sql database", "azure_sql"),
    ("cosmos", "azure_cosmos"),
    ("azure storage", "azure_storage"), ("blob storage", "azure_storage"), ("blob", "azure_storage"),
    ("key vault", "azure_keyvault"), ("keyvault", "azure_keyvault"),
    ("azure vm", "azure_vm"),
    ("aks", "azure_aks"),
    ("apim", "azure_apim"), ("api management", "azure_apim"),
    ("service bus", "azure_servicebus"), ("servicebus", "azure_servicebus"),
    ("entra", "entra_id"), ("azure ad", "entra_id"), ("aad", "entra_id"),
    # GCP
    ("gcs", "gcp_storage"), ("cloud storage", "gcp_storage"),
    ("cloud sql", "gcp_sql"),
    ("gke", "gcp_gke"),
    # Datastores
    ("postgres", "postgres"), ("postgresql", "postgres"),
    ("mongo", "mongodb"),
    ("redis", "redis"),
    ("kafka", "kafka"),
    # Generic
    ("database", "database"), ("storage", "storage"), ("queue", "queue"),
    ("api", "api"), ("endpoint", "endpoint"), ("vm", "vm"),
    ("identity", "identity"), ("user", "identity"),
    ("secret", "secret-store"), ("vault", "secret-store"),
    ("repo", "repo"), ("repository", "repo"),
]
_DEFAULT_STYLE = (
    "rounded=1;whiteSpace=wrap;html=1;arcSize=10;fillColor=#f5f5f5;strokeColor=#666666;"
)

# Severity-tinted edge style. Unencrypted flows highlighted in red, encrypted in green.
_EDGE_STYLE_ENCRYPTED = (
    "endArrow=classic;html=1;rounded=1;edgeStyle=orthogonalEdgeStyle;exitX=1;exitY=0.5;"
    "entryX=0;entryY=0.5;strokeColor=#82b366;strokeWidth=2;fontSize=11;"
)
_EDGE_STYLE_UNENCRYPTED = (
    "endArrow=classic;html=1;rounded=1;edgeStyle=orthogonalEdgeStyle;exitX=1;exitY=0.5;"
    "entryX=0;entryY=0.5;strokeColor=#b85450;strokeWidth=2;dashed=1;fontSize=11;"
)


def _safe(s: Any) -> str:
    return escape(str(s or "")).replace('"', "&quot;")


def _style_for(component_type: Optional[str], notes: Optional[str] = None) -> str:
    """Pick the right mxGraph style for a component.

    Tries (in order):
      1. Direct match on a provider-specific key (`aws_s3`, `azure_keyvault`, ...)
      2. Substring hint match against `_TYPE_HINTS`
      3. Substring against notes (sometimes the provider hint lives there)
      4. Generic fallback
    """
    if not component_type:
        component_type = ""
    haystack = (component_type or "").lower().strip()
    if haystack in _TYPE_STYLE:
        return _TYPE_STYLE[haystack]
    extra = (notes or "").lower()
    full = f"{haystack} {extra}"
    for needle, target in _TYPE_HINTS:
        if needle in full and target in _TYPE_STYLE:
            return _TYPE_STYLE[target]
    return _DEFAULT_STYLE


def _bucket_by_zone(components: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group components by trust_zone, preserving input order within each zone."""
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for c in components or []:
        zone = (str(c.get("trust_zone") or "other").lower().strip()) or "other"
        if zone not in _ZONE_ORDER:
            zone = "other"
        buckets.setdefault(zone, []).append(c)
    return buckets


def _edge_label(flow: Dict[str, Any]) -> str:
    protocol = str(flow.get("protocol") or "").upper()
    data = str(flow.get("data") or "").lower()
    label = protocol
    if data and data != "other":
        label = f"{protocol} · {data}" if protocol else data
    if not flow.get("encrypted", True):
        label = f"{label} ⚠ unencrypted" if label else "⚠ unencrypted"
    return label.strip(" ·")


def render_drawio_xml(
    *,
    title: str,
    components: List[Dict[str, Any]],
    data_flows: List[Dict[str, Any]],
    executive_summary: Optional[str] = None,
) -> str:
    """Render the threat-model components + flows into an mxGraph XML string.

    The result is a complete `.drawio` file (single page, embedded inline)
    that diagrams.net can open natively."""
    buckets = _bucket_by_zone(components)
    active_zones = [z for z in _ZONE_ORDER if buckets.get(z)]
    if not active_zones:
        # No components — emit a minimal placeholder so the viewer doesn't blank out
        return _empty_drawio(title)

    # Pre-compute swimlane heights from component counts
    zone_heights: Dict[str, int] = {}
    for z in active_zones:
        n = len(buckets[z])
        zone_heights[z] = _SWIMLANE_TITLE_H + _SWIMLANE_PAD_Y + n * (_COMP_HEIGHT + _COMP_PAD_Y)
    page_height = max(zone_heights.values(), default=400) + 2 * _SWIMLANE_PAD_Y
    page_width = (
        _SWIMLANE_PAD_X * 2
        + len(active_zones) * _SWIMLANE_WIDTH
        + max(0, len(active_zones) - 1) * _SWIMLANE_GAP
    )

    # Track component_id → (zone, abs_x, abs_y) so edges can reference them
    comp_position: Dict[str, Tuple[str, int, int]] = {}

    cells: List[str] = [
        '<mxCell id="0" />',
        '<mxCell id="1" parent="0" />',
    ]

    # Swimlanes + components
    for col, zone in enumerate(active_zones):
        zone_x = _SWIMLANE_PAD_X + col * (_SWIMLANE_WIDTH + _SWIMLANE_GAP)
        zone_y = _SWIMLANE_PAD_Y
        zone_h = zone_heights[zone]
        zone_id = f"zone-{zone}"
        zone_style = (
            "swimlane;fontSize=14;fontStyle=1;startSize=30;html=1;whiteSpace=wrap;"
            "fillColor=#f5f5f5;strokeColor=#9eb9d8;swimlaneFillColor=#ffffff;"
        )
        cells.append(
            f'<mxCell id="{zone_id}" value="{_safe(_ZONE_LABEL[zone])}" '
            f'style="{zone_style}" vertex="1" parent="1">'
            f'<mxGeometry x="{zone_x}" y="{zone_y}" width="{_SWIMLANE_WIDTH}" '
            f'height="{zone_h}" as="geometry" /></mxCell>'
        )
        for i, comp in enumerate(buckets[zone]):
            cid = str(comp.get("id") or f"c-{zone}-{i}")
            comp_x = _COMP_INSET_X
            comp_y = _SWIMLANE_TITLE_H + _SWIMLANE_PAD_Y + i * (_COMP_HEIGHT + _COMP_PAD_Y)
            name = str(comp.get("name") or cid)
            crit = str(comp.get("criticality") or "").lower()
            badge = ""
            if crit in ("critical", "high"):
                badge = f"\n[{crit.upper()}]"
            label = f"{name}{badge}"
            style = _style_for(comp.get("type"), comp.get("notes"))
            cells.append(
                f'<mxCell id="{_safe(cid)}" value="{_safe(label)}" '
                f'style="{style}" vertex="1" parent="{zone_id}">'
                f'<mxGeometry x="{comp_x}" y="{comp_y}" '
                f'width="{_COMP_WIDTH}" height="{_COMP_HEIGHT}" as="geometry" /></mxCell>'
            )
            comp_position[cid] = (zone, zone_x + comp_x, zone_y + comp_y)

    # Edges — keep all known component IDs so we can drop dangling references
    known_ids = set(comp_position.keys())
    for i, flow in enumerate(data_flows or []):
        src = str(flow.get("from") or "")
        dst = str(flow.get("to") or "")
        if not src or not dst or src not in known_ids or dst not in known_ids:
            continue
        encrypted = flow.get("encrypted", True)
        if isinstance(encrypted, str):
            encrypted = encrypted.lower() not in ("false", "0", "no", "")
        style = _EDGE_STYLE_ENCRYPTED if encrypted else _EDGE_STYLE_UNENCRYPTED
        cells.append(
            f'<mxCell id="edge-{i}" value="{_safe(_edge_label(flow))}" '
            f'style="{style}" edge="1" parent="1" '
            f'source="{_safe(src)}" target="{_safe(dst)}">'
            f'<mxGeometry relative="1" as="geometry" /></mxCell>'
        )

    # Optional executive-summary banner across the top
    banner = ""
    if executive_summary:
        banner = (
            f'<mxCell id="summary" value="{_safe(executive_summary)}" '
            f'style="text;html=1;align=left;verticalAlign=middle;whiteSpace=wrap;'
            f'fillColor=#fff8dc;strokeColor=#d6b656;fontSize=11;" vertex="1" parent="1">'
            f'<mxGeometry x="{_SWIMLANE_PAD_X}" y="4" '
            f'width="{page_width - 2 * _SWIMLANE_PAD_X}" height="32" as="geometry" /></mxCell>'
        )
        cells.insert(2, banner)
        # Shift swimlanes down by 36 — easier to just re-render? Keep simple:
        # we already laid out at _SWIMLANE_PAD_Y so banner sits above.
        # In practice the banner is at y=4 (height 32) and swimlanes at y=40, which fits.

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="NexGenCyberAI" version="22.0.0" type="device">\n'
        f'<diagram name="{_safe(title)}" id="threat-model">\n'
        f'<mxGraphModel dx="{page_width}" dy="{page_height}" grid="1" gridSize="10" '
        'guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        f'pageWidth="{max(page_width + 40, 850)}" pageHeight="{max(page_height + 40, 1100)}" '
        'math="0" shadow="0">\n'
        '<root>\n'
        + "\n".join(cells)
        + '\n</root>\n</mxGraphModel>\n</diagram>\n</mxfile>\n'
    )


def _empty_drawio(title: str) -> str:
    """Fallback placeholder when there are no components yet."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="NexGenCyberAI" version="22.0.0" type="device">\n'
        f'<diagram name="{_safe(title)}" id="empty">\n'
        '<mxGraphModel dx="800" dy="600" grid="1" gridSize="10" guides="1" tooltips="1" '
        'connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="850" '
        'pageHeight="600" math="0" shadow="0">\n'
        '<root>\n'
        '<mxCell id="0" />\n'
        '<mxCell id="1" parent="0" />\n'
        '<mxCell id="msg" value="No components in this threat model yet." '
        'style="text;html=1;align=center;verticalAlign=middle;fontSize=14;fontStyle=2;'
        'fillColor=#f5f5f5;strokeColor=#999999;" vertex="1" parent="1">\n'
        '<mxGeometry x="200" y="220" width="450" height="60" as="geometry" />\n'
        '</mxCell>\n'
        '</root>\n</mxGraphModel>\n</diagram>\n</mxfile>\n'
    )
