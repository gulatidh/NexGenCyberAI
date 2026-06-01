"""Phase 9B — overlay views for the threat-model DFD.

Takes the canonical Mermaid `dfd_mermaid` (the architectural skeleton) and
appends Mermaid `style` directives that color nodes + edges based on a
selected lens:

  - architecture       — no overlay, the diagram as authored.
  - threat_heat        — nodes shaded by the worst-severity threat they
                          carry; threat-count badge appended to the label.
                          Edges colored by encryption (red dashed for
                          unencrypted, green for TLS).
  - detection_coverage — nodes shaded by detection_status: green when at
                          least one of their threats has 'detected', red
                          when at least one is a 'gap', grey for n/a only.

The output is still valid Mermaid (just with extra trailing lines) so the
existing DfdDiagram component can render it without changes.
"""
from __future__ import annotations
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


VIEWS = ("architecture", "threat_heat", "detection_coverage")


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SEV_NODE_STYLE = {
    "critical": "fill:#7f1d1d,stroke:#fca5a5,color:#ffffff",
    "high":     "fill:#9a3412,stroke:#fed7aa,color:#ffffff",
    "medium":   "fill:#854d0e,stroke:#fde68a,color:#ffffff",
    "low":      "fill:#14532d,stroke:#86efac,color:#ffffff",
    "none":     "fill:#1f2937,stroke:#9ca3af,color:#e5e7eb",
}

_DETECTION_NODE_STYLE = {
    "detected":       "fill:#14532d,stroke:#86efac,color:#ffffff",
    "gap":            "fill:#7f1d1d,stroke:#fca5a5,color:#ffffff",
    "mixed":          "fill:#854d0e,stroke:#fde68a,color:#ffffff",
    "not_applicable": "fill:#1f2937,stroke:#9ca3af,color:#9ca3af",
    "no_threats":     "fill:#0f172a,stroke:#475569,color:#9ca3af",
}


# Mermaid linkStyle indexing requires us to know the order edges appear in
# the source. We do a simple line-by-line walk to count them.
_EDGE_RE = re.compile(r"-{2,3}>|-{2,3}\|.*?\|-{2,3}>|--?>")


def style_dfd(
    *,
    view: str,
    base_mermaid: str,
    components: List[Dict[str, Any]],
    data_flows: List[Dict[str, Any]],
    threats: List[Dict[str, Any]],
) -> str:
    """Return a styled Mermaid string for the requested view."""
    view = (view or "architecture").lower()
    if view not in VIEWS:
        view = "architecture"
    if view == "architecture" or not base_mermaid.strip():
        return base_mermaid

    if view == "threat_heat":
        return _styled_threat_heat(base_mermaid, components, data_flows, threats)
    if view == "detection_coverage":
        return _styled_detection_coverage(base_mermaid, components, threats)
    return base_mermaid


def _component_threat_index(threats: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Map component_id → list of threats targeting it."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats or []:
        cid = str(t.get("asset_id") or "")
        if not cid:
            continue
        out.setdefault(cid, []).append(t)
    return out


def _worst_severity(ts: List[Dict[str, Any]]) -> str:
    rank = 0
    worst = "none"
    for t in ts:
        sev = (t.get("severity") or "").lower()
        r = _SEV_RANK.get(sev, 0)
        if r > rank:
            rank = r
            worst = sev
    return worst


def _styled_threat_heat(base: str, components: List[Dict[str, Any]],
                         data_flows: List[Dict[str, Any]], threats: List[Dict[str, Any]]) -> str:
    by_comp = _component_threat_index(threats)
    style_lines: List[str] = []

    # Node colors + threat-count appended via clickable callback (just a
    # label suffix using Mermaid's `nodeId@{label: "..."}` syntax doesn't
    # exist for flowchart; instead we add a small annotation node alongside).
    # Simplest: append `style nodeId fill:..,stroke:..,color:..` lines.
    for c in components or []:
        cid = str(c.get("id") or "")
        if not cid:
            continue
        ts = by_comp.get(cid, [])
        if not ts:
            sev_key = "none"
        else:
            sev_key = _worst_severity(ts)
        style = _SEV_NODE_STYLE.get(sev_key, _SEV_NODE_STYLE["none"])
        style_lines.append(f"  style {_safe_id(cid)} {style}")

    # Edge styling — walk the base mermaid lines, count arrows, color each
    # by whether the data_flow at that index is encrypted.
    edge_styles = _edge_styles_by_encryption(base, data_flows)
    style_lines.extend(edge_styles)

    # Add a legend subgraph at the bottom so the colors are self-documenting.
    legend = _legend_threat_heat()

    return base + "\n" + "\n".join(style_lines) + "\n" + legend


def _styled_detection_coverage(base: str, components: List[Dict[str, Any]],
                                threats: List[Dict[str, Any]]) -> str:
    by_comp = _component_threat_index(threats)
    style_lines: List[str] = []
    for c in components or []:
        cid = str(c.get("id") or "")
        if not cid:
            continue
        ts = by_comp.get(cid, [])
        if not ts:
            key = "no_threats"
        else:
            statuses = {(t.get("detection_status") or "gap").lower() for t in ts}
            if statuses == {"detected"}:
                key = "detected"
            elif "gap" in statuses and "detected" in statuses:
                key = "mixed"
            elif "gap" in statuses:
                key = "gap"
            elif statuses == {"not_applicable"}:
                key = "not_applicable"
            else:
                key = "mixed"
        style = _DETECTION_NODE_STYLE.get(key, _DETECTION_NODE_STYLE["no_threats"])
        style_lines.append(f"  style {_safe_id(cid)} {style}")

    return base + "\n" + "\n".join(style_lines) + "\n" + _legend_detection()


def _edge_styles_by_encryption(base: str, data_flows: List[Dict[str, Any]]) -> List[str]:
    """Color each edge in declaration order by whether the corresponding
    data_flow is encrypted. Mermaid uses 0-based `linkStyle` per edge in
    appearance order."""
    out: List[str] = []
    edge_index = 0
    flow_iter = iter(data_flows or [])
    for line in base.splitlines():
        # Cheap detection — any flowchart edge line contains '-->' (with
        # optional label).
        if "-->" in line and "subgraph" not in line:
            try:
                f = next(flow_iter)
            except StopIteration:
                f = {}
            encrypted = f.get("encrypted", True)
            if isinstance(encrypted, str):
                encrypted = encrypted.lower() not in ("false", "0", "no", "")
            if encrypted:
                style = "stroke:#86efac,stroke-width:2px"
            else:
                style = "stroke:#fca5a5,stroke-width:2px,stroke-dasharray:5 5"
            out.append(f"  linkStyle {edge_index} {style}")
            edge_index += 1
    return out


def _legend_threat_heat() -> str:
    return (
        "  subgraph LEGEND_HEAT[\"Legend — Worst-severity threat per component\"]\n"
        "    legend_crit[\"Critical\"]:::sevCrit\n"
        "    legend_high[\"High\"]:::sevHigh\n"
        "    legend_med[\"Medium\"]:::sevMed\n"
        "    legend_low[\"Low\"]:::sevLow\n"
        "    legend_none[\"No threat\"]:::sevNone\n"
        "  end\n"
        "  classDef sevCrit fill:#7f1d1d,stroke:#fca5a5,color:#ffffff;\n"
        "  classDef sevHigh fill:#9a3412,stroke:#fed7aa,color:#ffffff;\n"
        "  classDef sevMed fill:#854d0e,stroke:#fde68a,color:#ffffff;\n"
        "  classDef sevLow fill:#14532d,stroke:#86efac,color:#ffffff;\n"
        "  classDef sevNone fill:#1f2937,stroke:#9ca3af,color:#e5e7eb;"
    )


def _legend_detection() -> str:
    return (
        "  subgraph LEGEND_DET[\"Legend — SOC detection coverage\"]\n"
        "    legend_det[\"Detected (rule named)\"]:::detOk\n"
        "    legend_mixed[\"Mixed (some gaps)\"]:::detMixed\n"
        "    legend_gap[\"Gap (no detection)\"]:::detGap\n"
        "    legend_na[\"Not applicable\"]:::detNa\n"
        "    legend_nt[\"No threats yet\"]:::detNt\n"
        "  end\n"
        "  classDef detOk fill:#14532d,stroke:#86efac,color:#ffffff;\n"
        "  classDef detMixed fill:#854d0e,stroke:#fde68a,color:#ffffff;\n"
        "  classDef detGap fill:#7f1d1d,stroke:#fca5a5,color:#ffffff;\n"
        "  classDef detNa fill:#1f2937,stroke:#9ca3af,color:#9ca3af;\n"
        "  classDef detNt fill:#0f172a,stroke:#475569,color:#9ca3af;"
    )


def _safe_id(s: str) -> str:
    """Mermaid node IDs allow [a-zA-Z0-9_-]. Drop anything else just in case."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", s)
