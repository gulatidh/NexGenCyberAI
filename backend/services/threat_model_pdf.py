"""Phase 8F — server-rendered, print-ready threat-model deliverable.

Returns a fully self-contained HTML document with embedded print CSS.
The frontend opens this URL in a new tab; the user prints to PDF from
there (Ctrl+P → Save as PDF). The output is consultant-grade because:

  - No AppLayout shell to fight (no sidebar, no overflow, no flex).
  - Strict print CSS with @page rules and break-inside controls.
  - Light theme baked in — readable on paper.
  - All sections (cover, exec summary, components, DFD, coverage matrix,
    threats grouped by component, mitigations table, maturity radar,
    sign-off) on the page in the right order.

This intentionally avoids WeasyPrint / wkhtmltopdf so we don't need
system-level native deps in the deployment environment.
"""
from __future__ import annotations
import html as html_lib
import io
import json
from datetime import datetime
from typing import Any, Dict, FrozenSet, List, Optional

from api.models.models import ThreatModel

_ALL_SECTIONS: FrozenSet[str] = frozenset([
    "cover", "exec_summary", "architecture", "boundaries",
    "risk_matrix", "coverage_matrix", "maturity", "threats", "mitigations", "signoff",
])


def _h(s: Any) -> str:
    """HTML-escape."""
    return html_lib.escape(str(s) if s is not None else "")


def _pct(v: float) -> str:
    return f"{round(v * 100):.0f}%"


_SEV_BG = {"critical": "#fee2e2", "high": "#ffedd5", "medium": "#fef3c7", "low": "#dcfce7"}
_SEV_FG = {"critical": "#991b1b", "high": "#9a3412", "medium": "#92400e", "low": "#166534"}
_STATE_BG = {"threat": "#fee2e2", "considered": "#e0e7ff", "not_applicable": "#f1f5f9", "missing": "#fef3c7"}
_STATE_FG = {"threat": "#991b1b", "considered": "#3730a3", "not_applicable": "#475569", "missing": "#92400e"}


def _heatmap_cell_color(score: int) -> tuple[str, str]:
    """Return (bg, fg) for a likelihood*impact score."""
    if score >= 16:
        return "#fee2e2", "#991b1b"   # critical
    if score >= 9:
        return "#ffedd5", "#9a3412"   # high
    if score >= 4:
        return "#fef3c7", "#92400e"   # medium
    return "#dcfce7", "#166534"       # low


def render_threat_model_html(
    tm: ThreatModel,
    *,
    client_name: str = "Unknown Client",
    sections: Optional[FrozenSet[str]] = None,
) -> str:
    sec = sections if sections is not None else _ALL_SECTIONS

    components: List[Dict[str, Any]] = tm.components_json or []
    data_flows: List[Dict[str, Any]] = tm.data_flows_json or []
    threats: List[Dict[str, Any]] = tm.threats_json or []
    mitigations: List[Dict[str, Any]] = tm.mitigations_json or []
    coverage: List[Dict[str, Any]] = tm.coverage_decisions or []
    trust_boundaries: List[Dict[str, Any]] = tm.trust_boundaries_json or []
    entry_points: List[Dict[str, Any]] = tm.entry_points_json or []
    maturity: Dict[str, float] = tm.maturity_scores or {}

    methodology = (tm.methodology or "stride").upper()
    title = tm.name or f"Threat Model · {methodology}"
    date_str = (tm.generated_at or datetime.utcnow()).strftime("%d %B %Y")
    threat_count = len(threats)
    component_count = len(components)
    mitigation_count = len(mitigations)
    coverage_pct = 0
    if coverage:
        non_missing = sum(1 for d in coverage if d.get("state") != "missing")
        coverage_pct = round((non_missing / len(coverage)) * 100, 1)
    grounded = sum(1 for t in threats if t.get("is_grounded"))

    comp_by_id = {str(c.get("id")): c for c in components}

    parts: List[str] = []

    if "cover" in sec:
        parts.append(_cover(title, client_name, methodology, date_str,
                            threat_count, component_count, mitigation_count, coverage_pct, grounded))
    if "exec_summary" in sec:
        parts.append(_exec_summary(tm.executive_summary or ""))
    if "architecture" in sec:
        parts.append(_completeness_section(components, data_flows, trust_boundaries, entry_points))
    if "boundaries" in sec:
        parts.append(_boundaries_section(trust_boundaries, entry_points, data_flows))
    if "risk_matrix" in sec:
        parts.append(_risk_heatmap_section(threats))
    if "coverage_matrix" in sec:
        parts.append(_coverage_matrix(components, coverage, threats))
    if "maturity" in sec:
        parts.append(_maturity_section(maturity))
    if "threats" in sec:
        parts.append(_threats_section(threats, mitigations, comp_by_id))
    if "mitigations" in sec:
        parts.append(_mitigations_table(mitigations))
    if "signoff" in sec:
        parts.append(_signoff())

    body = "\n".join(p for p in parts if p)
    return _wrap_document(title, client_name, body)


# ── Document chrome ─────────────────────────────────────────────────────────


_PRINT_CSS = """
@page {
  size: A4;
  margin: 14mm 13mm 18mm 13mm;
  @bottom-center { content: counter(page) " / " counter(pages); font-size: 9pt; color: #6b7280; }
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  font-family: "Inter", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  color: #0f172a; background: #ffffff;
  font-size: 11pt; line-height: 1.5;
}
h1 { font-size: 22pt; font-weight: 700; letter-spacing: -0.02em; color: #0f172a; margin: 0 0 6pt; }
h2 { font-size: 14pt; font-weight: 700; margin: 18pt 0 8pt; color: #1e293b; border-bottom: 2px solid #1a73e8; padding-bottom: 4pt; }
h3 { font-size: 12pt; font-weight: 700; margin: 12pt 0 4pt; color: #1e293b; }
h4 { font-size: 11pt; font-weight: 700; margin: 8pt 0 4pt; color: #0f172a; }
p { margin: 0 0 6pt; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0 12pt; font-size: 9.5pt; }
th { background: #f1f5f9; color: #0f172a; font-weight: 700; text-align: left; padding: 5pt 7pt; border-bottom: 1px solid #cbd5e1; }
td { padding: 5pt 7pt; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
tr { page-break-inside: avoid; }
thead { display: table-header-group; }

.pill { display: inline-block; padding: 1.5pt 6pt; border-radius: 10pt; font-size: 8.5pt; font-weight: 700; line-height: 1.4; }
.muted { color: #64748b; font-size: 9.5pt; }
.label { font-size: 8pt; font-weight: 700; letter-spacing: 0.5pt; text-transform: uppercase; color: #475569; }

.cover { page-break-after: always; min-height: 230mm; display: flex; flex-direction: column; }
.cover-top { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1pt solid #cbd5e1; padding-bottom: 12pt; }
.cover-mid { flex: 1; display: flex; flex-direction: column; justify-content: center; }
.cover-mid h1 { font-size: 32pt; line-height: 1.1; }
.cover-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8pt 24pt; margin-top: 24pt; }
.cover-meta .label { display: block; margin-bottom: 2pt; }
.kpis { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8pt; margin-top: 20pt; }
.kpi { padding: 10pt; background: #f8fafc; border: 1pt solid #e2e8f0; border-radius: 6pt; }
.kpi-value { font-size: 18pt; font-weight: 700; color: #1a73e8; line-height: 1; }
.kpi-label { font-size: 8.5pt; color: #64748b; margin-top: 4pt; text-transform: uppercase; letter-spacing: 0.5pt; }
.brand { color: #1a73e8; font-weight: 700; letter-spacing: -0.01em; }

.section { page-break-inside: avoid; margin-bottom: 12pt; }
.threat-block { page-break-inside: avoid; margin-bottom: 14pt; padding: 8pt 10pt; border-left: 3pt solid #cbd5e1; background: #f8fafc; border-radius: 4pt; }
.threat-block.severity-critical { border-left-color: #991b1b; }
.threat-block.severity-high { border-left-color: #9a3412; }
.threat-block.severity-medium { border-left-color: #92400e; }
.threat-block.severity-low { border-left-color: #166534; }
.threat-meta { display: flex; flex-wrap: wrap; gap: 4pt; margin-bottom: 4pt; }

.matrix-grid { display: grid; gap: 2pt; font-size: 8.5pt; }
.matrix-cell { padding: 4pt 6pt; border-radius: 3pt; min-height: 24pt; }
.matrix-cell .label { font-size: 7pt; }
.matrix-header { font-weight: 700; padding: 4pt 6pt; color: #475569; text-transform: uppercase; font-size: 8pt; letter-spacing: 0.5pt; }

.maturity-radar { display: flex; flex-wrap: wrap; gap: 12pt; }
.maturity-card { flex: 1; min-width: 22%; padding: 8pt 10pt; background: #f8fafc; border: 1pt solid #e2e8f0; border-radius: 4pt; }
.maturity-bar { height: 6pt; background: #e2e8f0; border-radius: 3pt; margin-top: 4pt; overflow: hidden; }
.maturity-bar-fill { height: 100%; background: #1a73e8; border-radius: 3pt; }

.heatmap { display: grid; grid-template-columns: 28pt repeat(5, 1fr); gap: 2pt; font-size: 8.5pt; margin: 8pt 0; }
.heatmap-axis { display: flex; align-items: center; justify-content: center; font-weight: 700; color: #475569; font-size: 8pt; }
.heatmap-cell { padding: 6pt; border-radius: 3pt; text-align: center; min-height: 30pt; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.heatmap-count { font-size: 14pt; font-weight: 700; line-height: 1; }
.heatmap-label { font-size: 7pt; margin-top: 2pt; }

.signoff { margin-top: 24pt; page-break-inside: avoid; border-top: 1pt solid #cbd5e1; padding-top: 12pt; }
.signoff-row { display: grid; grid-template-columns: 1fr 1fr; gap: 24pt; margin-top: 16pt; }
.sign-line { border-bottom: 1pt solid #475569; height: 28pt; margin-bottom: 4pt; }
"""


def _wrap_document(title: str, client_name: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{_h(title)} — {_h(client_name)}</title>
  <style>{_PRINT_CSS}</style>
  <script>
    // Auto-trigger the print dialog once the document has rendered. The
    // consultant lands in their browser's "Save as PDF" flow without an
    // extra click.
    window.addEventListener("load", function() {{ setTimeout(function() {{ window.print(); }}, 350); }});
  </script>
</head>
<body>
{body_html}
</body>
</html>
"""


# ── Sections ────────────────────────────────────────────────────────────────


def _cover(title: str, client_name: str, methodology: str, date_str: str,
           threat_count: int, component_count: int, mitigation_count: int,
           coverage_pct: float, grounded: int) -> str:
    return f"""<div class="cover">
  <div class="cover-top">
    <div>
      <div class="brand" style="font-size: 14pt;">NexGen Cyber AI</div>
      <div class="muted" style="margin-top: 2pt;">Threat Model Deliverable · {_h(methodology)}</div>
    </div>
    <div style="text-align: right;">
      <div class="label">Date issued</div>
      <div style="font-size: 11pt; font-weight: 600;">{_h(date_str)}</div>
    </div>
  </div>
  <div class="cover-mid">
    <div class="label">Threat Model</div>
    <h1>{_h(title)}</h1>
    <div style="font-size: 14pt; color: #475569; margin-top: 6pt;">Prepared for <strong>{_h(client_name)}</strong></div>
    <div class="cover-meta">
      <div><span class="label">Methodology</span>{_h(methodology)}</div>
      <div><span class="label">Threats identified</span>{threat_count}</div>
      <div><span class="label">Components in scope</span>{component_count}</div>
      <div><span class="label">Proposed mitigations</span>{mitigation_count}</div>
      <div><span class="label">Coverage (cells filled)</span>{coverage_pct}%</div>
      <div><span class="label">Evidence-grounded threats</span>{grounded} / {threat_count}</div>
    </div>
    <div class="kpis">
      <div class="kpi"><div class="kpi-value">{threat_count}</div><div class="kpi-label">Threats</div></div>
      <div class="kpi"><div class="kpi-value">{component_count}</div><div class="kpi-label">Components</div></div>
      <div class="kpi"><div class="kpi-value">{mitigation_count}</div><div class="kpi-label">Mitigations</div></div>
      <div class="kpi"><div class="kpi-value">{coverage_pct}%</div><div class="kpi-label">Coverage</div></div>
      <div class="kpi"><div class="kpi-value">{grounded}/{threat_count or 1}</div><div class="kpi-label">Grounded</div></div>
    </div>
  </div>
  <div style="text-align: center; color: #64748b; font-size: 9pt; padding-top: 16pt;">
    Confidential — for {_h(client_name)} internal use only.
  </div>
</div>"""


def _exec_summary(text: str) -> str:
    body = _h(text).replace("\n\n", "</p><p>").replace("\n", " ")
    return f"""<section class="section">
  <h2>1. Executive Summary</h2>
  <p>{body or "(no executive summary captured)"}</p>
</section>"""


def _completeness_section(components: List[Dict[str, Any]], data_flows: List[Dict[str, Any]],
                           trust_boundaries: List[Dict[str, Any]], entry_points: List[Dict[str, Any]]) -> str:
    comp_rows = "\n".join(
        f"<tr><td>{_h(c.get('id'))}</td><td>{_h(c.get('name'))}</td><td>{_h(c.get('type'))}</td>"
        f"<td>{_h(c.get('trust_zone'))}</td><td>{_h(c.get('criticality'))}</td><td>{_h(c.get('notes'))}</td></tr>"
        for c in components
    )
    flow_rows = "\n".join(
        f"<tr><td>{_h(f.get('from'))}</td><td>{_h(f.get('to'))}</td><td>{_h(f.get('protocol'))}</td>"
        f"<td>{_h(f.get('data'))}</td><td>{'Yes' if f.get('encrypted') else 'No'}</td>"
        f"<td>{'⚠ Crosses boundary' if f.get('trust_boundary_crossing') else '—'}</td></tr>"
        for f in data_flows
    )
    return f"""<section class="section">
  <h2>2. Architecture &amp; Components</h2>
  <h3>Components ({len(components)})</h3>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Trust zone</th><th>Criticality</th><th>Notes</th></tr></thead>
    <tbody>{comp_rows or "<tr><td colspan='6' class='muted'>(no components)</td></tr>"}</tbody>
  </table>
  <h3>Data Flows ({len(data_flows)})</h3>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Data</th><th>Encrypted</th><th>Boundary</th></tr></thead>
    <tbody>{flow_rows or "<tr><td colspan='6' class='muted'>(no data flows)</td></tr>"}</tbody>
  </table>
</section>"""


def _boundaries_section(trust_boundaries: List[Dict[str, Any]], entry_points: List[Dict[str, Any]],
                         data_flows: List[Dict[str, Any]]) -> str:
    tb_rows = "\n".join(
        f"<tr><td>{_h(t.get('name'))}</td>"
        f"<td>{_h(t.get('from_zone'))}</td>"
        f"<td>{_h(t.get('to_zone'))}</td>"
        f"<td>{_h(t.get('description'))}</td>"
        f"<td style='text-align:center;'>{len(t.get('crossed_by_flow_ids') or [])}</td></tr>"
        for t in trust_boundaries
    ) or "<tr><td colspan='5' class='muted'>(no trust boundaries enumerated)</td></tr>"

    ep_rows = "\n".join(
        f"<tr><td>{_h(e.get('name'))}</td>"
        f"<td>{_h(e.get('kind'))}</td>"
        f"<td>{_h(e.get('exposure'))}</td>"
        f"<td>{'Yes' if e.get('auth_required') else 'No'}</td>"
        f"<td>{_h(e.get('component_id'))}</td></tr>"
        for e in entry_points
    ) or "<tr><td colspan='5' class='muted'>(no entry points enumerated)</td></tr>"

    crossing_flows = [f for f in data_flows if f.get("trust_boundary_crossing")]
    cf_rows = "\n".join(
        f"<tr><td>{_h(f.get('from'))}</td><td>{_h(f.get('to'))}</td>"
        f"<td>{_h(f.get('protocol'))}</td><td>{_h(f.get('data'))}</td></tr>"
        for f in crossing_flows
    ) or "<tr><td colspan='4' class='muted'>(no boundary-crossing flows)</td></tr>"

    return f"""<section class="section" style="page-break-before: always;">
  <h2>3. Trust Boundaries &amp; Entry Points</h2>
  <h3>Trust Boundaries ({len(trust_boundaries)})</h3>
  <table>
    <thead><tr><th>Name</th><th>From Zone</th><th>To Zone</th><th>Description</th><th>Crossing Flows</th></tr></thead>
    <tbody>{tb_rows}</tbody>
  </table>
  <h3>Entry Points ({len(entry_points)})</h3>
  <table>
    <thead><tr><th>Name</th><th>Kind</th><th>Exposure</th><th>Auth Required</th><th>Component</th></tr></thead>
    <tbody>{ep_rows}</tbody>
  </table>
  <h3>Boundary-Crossing Flows ({len(crossing_flows)})</h3>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Data</th></tr></thead>
    <tbody>{cf_rows}</tbody>
  </table>
</section>"""


def _risk_heatmap_section(threats: List[Dict[str, Any]]) -> str:
    # Build count map: (likelihood, impact) → count
    cell_counts: Dict[tuple, int] = {}
    for t in threats:
        li = int(t.get("likelihood") or 0)
        im = int(t.get("impact") or 0)
        if 1 <= li <= 5 and 1 <= im <= 5:
            cell_counts[(li, im)] = cell_counts.get((li, im), 0) + 1

    # Build grid HTML: rows = impact 5 (top) → 1 (bottom), cols = likelihood 1→5
    # Layout: first col = impact label, then 5 likelihood cols
    header_row = '<div class="heatmap-axis">Impact ↕</div>'
    for li in range(1, 6):
        header_row += f'<div class="heatmap-axis">L{li}</div>'

    rows_html = ""
    for im in range(5, 0, -1):
        rows_html += f'<div class="heatmap-axis">I{im}</div>'
        for li in range(1, 6):
            score = li * im
            bg, fg = _heatmap_cell_color(score)
            count = cell_counts.get((li, im), 0)
            count_html = f'<div class="heatmap-count" style="color:{fg};">{count}</div>' if count > 0 else '<div class="heatmap-count" style="color:#94a3b8;">·</div>'
            rows_html += (
                f'<div class="heatmap-cell" style="background:{bg};">'
                f'{count_html}'
                f'<div class="heatmap-label" style="color:{fg};">{score}</div>'
                f'</div>'
            )

    total_placed = sum(cell_counts.values())
    unplaced = len(threats) - total_placed

    note = ""
    if unplaced > 0:
        note = f'<p class="muted">{unplaced} threat{"s" if unplaced != 1 else ""} have no likelihood/impact score and are not plotted.</p>'

    return f"""<section class="section" style="page-break-before: always;">
  <h2>4. Risk Heat Map</h2>
  <p class="muted">Threats plotted by likelihood (X-axis, 1–5) × impact (Y-axis, 1–5). Cell score = L×I. Colour: ≥16 critical, ≥9 high, ≥4 medium, &lt;4 low.</p>
  <div class="heatmap">
    {header_row}
    {rows_html}
  </div>
  {note}
</section>"""


def _coverage_matrix(components: List[Dict[str, Any]], coverage: List[Dict[str, Any]], threats: List[Dict[str, Any]]) -> str:
    if not components or not coverage:
        return ""
    categories = sorted({d.get("category") for d in coverage if d.get("category")})
    by_cell = {}
    for d in coverage:
        by_cell[(d.get("component_id"), d.get("category"))] = d
    col_template = f"grid-template-columns: 22% repeat({len(categories)}, 1fr);"

    header_cells = ['<div class="matrix-header">Component</div>'] + [
        f'<div class="matrix-header">{_h(c.replace("_", " ").title())}</div>' for c in categories
    ]
    rows_html = []
    for c in components:
        cells = [f'<div class="matrix-cell" style="font-weight:600;">{_h(c.get("name"))}</div>']
        for cat in categories:
            d = by_cell.get((str(c.get("id")), cat))
            if d:
                state = d.get("state", "missing")
                bg = _STATE_BG.get(state, "#f1f5f9")
                fg = _STATE_FG.get(state, "#475569")
                if state == "threat":
                    label = "Threat"
                elif state == "considered":
                    label = "Considered"
                elif state == "not_applicable":
                    label = "N/A"
                else:
                    label = "Missing"
                rationale_short = _h((d.get("rationale") or "")[:80])
                cells.append(
                    f'<div class="matrix-cell" style="background:{bg};color:{fg};">'
                    f'<div class="label">{label}</div>'
                    f'<div style="font-size:7.5pt;line-height:1.3;">{rationale_short}</div>'
                    f'</div>'
                )
            else:
                cells.append('<div class="matrix-cell" style="background:#fafafa;">—</div>')
        rows_html.append("".join(cells))

    return f"""<section class="section" style="page-break-before: always;">
  <h2>5. STRIDE Coverage Matrix</h2>
  <p class="muted">Each cell shows the state of the (component × category) coverage decision. Threat cells contain at least one identified threat; Considered cells were analysed and dismissed with rationale; N/A cells are not applicable to that component; Missing cells require follow-up.</p>
  <div class="matrix-grid" style="{col_template}">
    {''.join(header_cells)}
    {''.join(rows_html)}
  </div>
</section>"""


def _maturity_section(maturity: Dict[str, float]) -> str:
    if not maturity:
        return ""
    cards = []
    for cat, score in sorted(maturity.items()):
        pct = max(0.0, min(1.0, float(score) / 5.0))
        cards.append(f"""<div class="maturity-card">
  <div class="label">{_h(cat.replace('_', ' ').title())}</div>
  <div style="font-size: 18pt; font-weight: 700; color: #1a73e8; margin-top: 2pt;">{score:.1f}<span style="font-size: 10pt; color: #64748b; font-weight: 400;"> / 5.0</span></div>
  <div class="maturity-bar"><div class="maturity-bar-fill" style="width: {_pct(pct)};"></div></div>
</div>""")
    return f"""<section class="section">
  <h2>6. Maturity by Category</h2>
  <p class="muted">Score 0-5 per category, derived from threat status, detection coverage, evidence quality, and unmitigated critical/high count.</p>
  <div class="maturity-radar">{''.join(cards)}</div>
</section>"""


def _threats_section(threats: List[Dict[str, Any]], mitigations: List[Dict[str, Any]], comp_by_id: Dict[str, Dict[str, Any]]) -> str:
    if not threats:
        return ""
    by_comp: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats:
        by_comp.setdefault(str(t.get("asset_id")) or "(unscoped)", []).append(t)
    mit_by_threat: Dict[str, List[Dict[str, Any]]] = {}
    for m in mitigations:
        mit_by_threat.setdefault(str(m.get("threat_id")), []).append(m)

    blocks = []
    for comp_id, t_list in by_comp.items():
        comp = comp_by_id.get(comp_id, {})
        comp_name = comp.get("name") or comp_id
        blocks.append(f"<h3>{_h(comp_name)} <span class='muted'>({len(t_list)} threats)</span></h3>")
        for t in sorted(t_list, key=lambda x: x.get("priority_score", 0), reverse=True):
            sev = (t.get("severity") or "medium").lower()
            sev_bg = _SEV_BG.get(sev, "#f1f5f9")
            sev_fg = _SEV_FG.get(sev, "#475569")
            refs = t.get("evidence_refs") or []
            ref_pills = " ".join(
                f"<span class='pill' style='background:#e0e7ff;color:#3730a3;'>{_h(r.get('kind'))}:{_h(r.get('id'))}</span>"
                for r in refs[:6]
            )
            capec_pills = " ".join(f"<span class='pill' style='background:#dcfce7;color:#166534;'>{_h(c)}</span>" for c in (t.get("capec_refs") or [])[:4])
            attack_pills = " ".join(f"<span class='pill' style='background:#fef3c7;color:#92400e;'>{_h(a)}</span>" for a in (t.get("attack_techniques") or [])[:4])
            cwe_pills = " ".join(f"<span class='pill' style='background:#fee2e2;color:#991b1b;'>{_h(c)}</span>" for c in (t.get("cwe_refs") or [])[:4])
            status = t.get("status") or "identified"
            det = t.get("detection_status") or "gap"
            blast = ", ".join(_h(b) for b in (t.get("blast_radius") or [])[:8]) or "—"
            mits = mit_by_threat.get(str(t.get("id")), [])
            mit_html = ""
            if mits:
                mit_html = "<h4>Mitigations</h4><ul>" + "".join(
                    f"<li><strong>{_h(m.get('action'))}</strong>"
                    f"<div class='muted'>{_h(m.get('implementation_detail') or '(no implementation detail)')}</div>"
                    + ("<div class='muted'>Controls: " + ", ".join(
                        f"{_h(r.get('framework'))}:{_h(r.get('control_id'))}" for r in (m.get('control_refs') or [])
                    ) + "</div>" if m.get("control_refs") else "")
                    + f"<div class='muted'>Owner: {_h(m.get('owner_role') or m.get('owner') or '—')} · Status: {_h(m.get('status') or 'open')}</div>"
                    + "</li>" for m in mits
                ) + "</ul>"
            blocks.append(f"""<div class="threat-block severity-{sev}">
  <div class="threat-meta">
    <span class="pill" style="background:{sev_bg};color:{sev_fg};">{_h(sev).upper()}</span>
    <span class="pill" style="background:#f1f5f9;color:#475569;">{_h(t.get('category', '').replace('_', ' ').title())}</span>
    <span class="pill" style="background:#e0e7ff;color:#3730a3;">P {t.get('priority_score', '—')}</span>
    <span class="pill" style="background:#f1f5f9;color:#475569;">L{t.get('likelihood', '—')} · I{t.get('impact', '—')}</span>
    <span class="pill" style="background:{('#dcfce7' if det=='detected' else '#fee2e2')};color:{('#166534' if det=='detected' else '#991b1b')};">Detection: {_h(det)}</span>
    <span class="pill" style="background:#f1f5f9;color:#475569;">Status: {_h(status)}</span>
    {'<span class="pill" style="background:#fee2e2;color:#991b1b;">UNGROUNDED</span>' if not t.get('is_grounded') else ''}
  </div>
  <h4>{_h(t.get('title'))}</h4>
  <p><strong class="label">Rationale</strong><br/>{_h(t.get('rationale'))}</p>
  {f"<p><strong class='label'>Attack narrative</strong><br/>{_h(t.get('attack_narrative'))}</p>" if t.get('attack_narrative') else ''}
  <p><strong class="label">Blast radius</strong><br/>{blast}</p>
  <div class="threat-meta" style="margin-top:4pt;">{ref_pills} {capec_pills} {attack_pills} {cwe_pills}</div>
  {mit_html}
</div>""")
    return f"""<section class="section" style="page-break-before: always;">
  <h2>7. Threats by Component</h2>
  {''.join(blocks)}
</section>"""


def _mitigations_table(mitigations: List[Dict[str, Any]]) -> str:
    if not mitigations:
        return ""
    def _ctrl_refs(m: Dict[str, Any]) -> str:
        return ", ".join(
            f"{_h(r.get('framework'))}:{_h(r.get('control_id'))}"
            for r in (m.get("control_refs") or [])
        )
    rows = "\n".join(
        f"<tr><td>{_h(m.get('id'))}</td><td>{_h(m.get('threat_id'))}</td>"
        f"<td>{_h(m.get('action'))}</td>"
        f"<td>{_ctrl_refs(m)}</td>"
        f"<td>{_h(m.get('owner_role') or m.get('owner') or '—')}</td>"
        f"<td>{_h(m.get('status') or 'open')}</td></tr>"
        for m in mitigations
    )
    return f"""<section class="section" style="page-break-before: always;">
  <h2>8. Mitigation Roadmap</h2>
  <table>
    <thead><tr><th>ID</th><th>Threat</th><th>Action</th><th>Control refs</th><th>Owner</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _signoff() -> str:
    return f"""<section class="signoff">
  <h2 style="border:none; padding:0; margin: 0 0 4pt;">Sign-off</h2>
  <p class="muted">This threat model is a point-in-time analysis. Sign below to acknowledge review and acceptance of the mitigation roadmap.</p>
  <div class="signoff-row">
    <div>
      <div class="sign-line"></div>
      <div class="label">Prepared by (NexGen consultant)</div>
    </div>
    <div>
      <div class="sign-line"></div>
      <div class="label">Accepted by (Customer, CISO or delegate)</div>
    </div>
  </div>
</section>"""


# ── Word (DOCX) export ───────────────────────────────────────────────────────


def render_threat_model_docx(
    tm: ThreatModel,
    *,
    client_name: str = "Unknown Client",
    sections: Optional[FrozenSet[str]] = None,
) -> bytes:
    from docx import Document
    from docx.shared import Pt, RGBColor, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    sec = sections if sections is not None else _ALL_SECTIONS

    components: List[Dict[str, Any]] = tm.components_json or []
    data_flows: List[Dict[str, Any]] = tm.data_flows_json or []
    threats: List[Dict[str, Any]] = tm.threats_json or []
    mitigations: List[Dict[str, Any]] = tm.mitigations_json or []
    trust_boundaries: List[Dict[str, Any]] = tm.trust_boundaries_json or []
    entry_points: List[Dict[str, Any]] = tm.entry_points_json or []
    maturity: Dict[str, float] = tm.maturity_scores or {}

    methodology = (tm.methodology or "stride").upper()
    title = tm.name or f"Threat Model · {methodology}"
    date_str = (tm.generated_at or datetime.utcnow()).strftime("%d %B %Y")

    doc = Document()

    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.5)

    def _blue_heading(text: str, level: int = 1):
        p = doc.add_heading(text, level=level)
        for run in p.runs:
            run.font.color.rgb = RGBColor(0x1A, 0x73, 0xE8)
        return p

    def _bold_table_header(tbl, headers):
        hdr = tbl.rows[0].cells
        for i, h in enumerate(headers):
            hdr[i].text = h
            for run in hdr[i].paragraphs[0].runs:
                run.bold = True

    # ── Cover ────────────────────────────────────────────────────────────────
    if "cover" in sec or "exec_summary" in sec:
        _blue_heading("NexGen Cyber AI — Threat Model Deliverable", level=1)
        p = doc.add_paragraph()
        p.add_run(title).bold = True
        p.runs[0].font.size = Pt(18)
        meta = doc.add_paragraph()
        meta.add_run(f"Client: {client_name}    Methodology: {methodology}    Date: {date_str}\n")
        meta.add_run(f"Threats: {len(threats)}    Components: {len(components)}    Mitigations: {len(mitigations)}")
        meta.paragraph_format.space_after = Pt(12)

    if "exec_summary" in sec:
        doc.add_page_break()
        _blue_heading("1. Executive Summary", level=2)
        doc.add_paragraph(tm.executive_summary or "(no executive summary captured)")

    # ── Architecture ─────────────────────────────────────────────────────────
    if "architecture" in sec:
        doc.add_page_break()
        _blue_heading("2. Architecture — Components", level=2)
        if components:
            tbl = doc.add_table(rows=1, cols=5)
            tbl.style = "Table Grid"
            _bold_table_header(tbl, ["ID", "Name", "Type", "Trust Zone", "Criticality"])
            for c in components:
                row = tbl.add_row().cells
                row[0].text = str(c.get("id") or "")
                row[1].text = str(c.get("name") or "")
                row[2].text = str(c.get("type") or "")
                row[3].text = str(c.get("trust_zone") or "")
                row[4].text = str(c.get("criticality") or "")
        else:
            doc.add_paragraph("(no components)")

        _blue_heading("2b. Data Flows", level=3)
        if data_flows:
            tbl = doc.add_table(rows=1, cols=5)
            tbl.style = "Table Grid"
            _bold_table_header(tbl, ["From", "To", "Protocol", "Data", "Boundary Crossing"])
            for f in data_flows:
                row = tbl.add_row().cells
                row[0].text = str(f.get("from") or "")
                row[1].text = str(f.get("to") or "")
                row[2].text = str(f.get("protocol") or "")
                row[3].text = str(f.get("data") or "")
                row[4].text = "Yes" if f.get("trust_boundary_crossing") else "No"
        else:
            doc.add_paragraph("(no data flows)")

    # ── Boundaries ───────────────────────────────────────────────────────────
    if "boundaries" in sec:
        doc.add_page_break()
        _blue_heading("3. Trust Boundaries & Entry Points", level=2)
        _blue_heading("Trust Boundaries", level=3)
        if trust_boundaries:
            tbl = doc.add_table(rows=1, cols=4)
            tbl.style = "Table Grid"
            _bold_table_header(tbl, ["Name", "From Zone → To Zone", "Description", "Crossing Flows"])
            for tb in trust_boundaries:
                row = tbl.add_row().cells
                row[0].text = str(tb.get("name") or "")
                row[1].text = f"{tb.get('from_zone', '')} → {tb.get('to_zone', '')}"
                row[2].text = str(tb.get("description") or "")
                row[3].text = str(len(tb.get("crossed_by_flow_ids") or []))
        else:
            doc.add_paragraph("(no trust boundaries)")

        _blue_heading("Entry Points", level=3)
        if entry_points:
            tbl = doc.add_table(rows=1, cols=5)
            tbl.style = "Table Grid"
            _bold_table_header(tbl, ["Name", "Kind", "Exposure", "Auth Required", "Component"])
            for ep in entry_points:
                row = tbl.add_row().cells
                row[0].text = str(ep.get("name") or "")
                row[1].text = str(ep.get("kind") or "")
                row[2].text = str(ep.get("exposure") or "")
                row[3].text = "Yes" if ep.get("auth_required") else "No"
                row[4].text = str(ep.get("component_id") or "")
        else:
            doc.add_paragraph("(no entry points)")

    # ── Risk Heat Map ─────────────────────────────────────────────────────────
    if "risk_matrix" in sec:
        doc.add_page_break()
        _blue_heading("4. Risk Heat Map", level=2)
        doc.add_paragraph("Threats by likelihood (columns 1–5) × impact (rows 1–5). Score = L×I.")
        # Build 5x5 table (impact rows descending, likelihood cols ascending)
        tbl = doc.add_table(rows=6, cols=6)
        tbl.style = "Table Grid"
        # Header row
        tbl.rows[0].cells[0].text = "Impact \\ Like."
        for li in range(1, 6):
            tbl.rows[0].cells[li].text = f"L{li}"
        # Data rows
        cell_counts: Dict[tuple, int] = {}
        for t in threats:
            li = int(t.get("likelihood") or 0)
            im = int(t.get("impact") or 0)
            if 1 <= li <= 5 and 1 <= im <= 5:
                cell_counts[(li, im)] = cell_counts.get((li, im), 0) + 1
        for ri, im in enumerate(range(5, 0, -1), start=1):
            tbl.rows[ri].cells[0].text = f"I{im}"
            for li in range(1, 6):
                count = cell_counts.get((li, im), 0)
                tbl.rows[ri].cells[li].text = str(count) if count > 0 else "·"

    # ── Threats by component ─────────────────────────────────────────────────
    if "threats" in sec:
        doc.add_page_break()
        _blue_heading("7. Threats by Component", level=2)
        comp_by_id = {str(c.get("id")): c for c in components}
        mit_by_threat: Dict[str, List[Dict[str, Any]]] = {}
        for m in mitigations:
            mit_by_threat.setdefault(str(m.get("threat_id")), []).append(m)
        by_comp: Dict[str, List[Dict[str, Any]]] = {}
        for t in threats:
            by_comp.setdefault(str(t.get("asset_id")) or "(unscoped)", []).append(t)
        if not threats:
            doc.add_paragraph("(no threats identified)")
        else:
            for comp_id, t_list in by_comp.items():
                comp = comp_by_id.get(comp_id, {})
                comp_name = comp.get("name") or comp_id
                _blue_heading(f"{comp_name} ({len(t_list)} threats)", level=3)
                for t in sorted(t_list, key=lambda x: x.get("priority_score", 0), reverse=True):
                    sev = (t.get("severity") or "medium").upper()
                    p = doc.add_paragraph(style="List Bullet")
                    p.add_run(f"[{sev}] {t.get('title') or '(untitled)'}").bold = True
                    doc.add_paragraph(f"L{t.get('likelihood','?')} × I{t.get('impact','?')} · P{t.get('priority_score','—')} · {t.get('status','identified')}")
                    if t.get("rationale"):
                        doc.add_paragraph(f"Rationale: {t.get('rationale')}")
                    mits = mit_by_threat.get(str(t.get("id")), [])
                    for m in mits:
                        doc.add_paragraph(f"  → {m.get('action', '')}", style="List Bullet 2")

    # ── Mitigations roadmap ──────────────────────────────────────────────────
    if "mitigations" in sec:
        doc.add_page_break()
        _blue_heading("8. Mitigation Roadmap", level=2)
        if mitigations:
            tbl = doc.add_table(rows=1, cols=5)
            tbl.style = "Table Grid"
            _bold_table_header(tbl, ["Threat ID", "Action", "Owner", "Status", "Control Refs"])
            for m in mitigations:
                ctrl_refs = ", ".join(
                    f"{r.get('framework')}:{r.get('control_id')}" for r in (m.get("control_refs") or [])
                )
                row = tbl.add_row().cells
                row[0].text = str(m.get("threat_id") or "")
                row[1].text = str(m.get("action") or "")
                row[2].text = str(m.get("owner_role") or m.get("owner") or "—")
                row[3].text = str(m.get("status") or "open")
                row[4].text = ctrl_refs or "—"
        else:
            doc.add_paragraph("(no mitigations)")

    # ── Maturity scores ──────────────────────────────────────────────────────
    if "maturity" in sec and maturity:
        doc.add_page_break()
        _blue_heading("6. Maturity by Category", level=2)
        tbl = doc.add_table(rows=1, cols=2)
        tbl.style = "Table Grid"
        _bold_table_header(tbl, ["Category", "Score (/ 5.0)"])
        for cat, score in sorted(maturity.items()):
            row = tbl.add_row().cells
            row[0].text = cat.replace("_", " ").title()
            row[1].text = f"{float(score):.1f}"

    # ── Sign-off ─────────────────────────────────────────────────────────────
    if "signoff" in sec:
        doc.add_page_break()
        _blue_heading("Sign-off", level=2)
        doc.add_paragraph("This threat model is a point-in-time analysis. Sign below to acknowledge review and acceptance of the mitigation roadmap.")
        doc.add_paragraph("\n\n")
        tbl = doc.add_table(rows=2, cols=2)
        tbl.style = "Table Grid"
        tbl.rows[0].cells[0].text = "Prepared by (NexGen consultant)"
        tbl.rows[0].cells[1].text = "Accepted by (Customer / CISO)"
        tbl.rows[1].cells[0].text = "\n\n"
        tbl.rows[1].cells[1].text = "\n\n"

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()


# ── Portal-style standalone HTML export ──────────────────────────────────────

def render_threat_model_portal_html(tm: ThreatModel, *, client_name: str = "Unknown Client") -> str:
    """Self-contained HTML that mirrors the portal's tab layout.

    Includes Mermaid.js (CDN) so the diagram renders in the browser.
    All sections are shown as tab panels with a top nav bar.
    Designed to be opened in any browser without a server.
    """
    components: List[Dict[str, Any]] = tm.components_json or []
    data_flows: List[Dict[str, Any]] = tm.data_flows_json or []
    threats: List[Dict[str, Any]] = tm.threats_json or []
    mitigations: List[Dict[str, Any]] = tm.mitigations_json or []
    coverage: List[Dict[str, Any]] = tm.coverage_decisions or []
    trust_boundaries: List[Dict[str, Any]] = tm.trust_boundaries_json or []
    entry_points: List[Dict[str, Any]] = tm.entry_points_json or []
    maturity: Dict[str, float] = tm.maturity_scores or {}
    sigma_rules: List[Dict[str, Any]] = tm.sigma_rules_json or []

    methodology = (tm.methodology or "stride").upper()
    title = tm.name or f"Threat Model · {methodology}"
    date_str = (tm.generated_at or datetime.utcnow()).strftime("%d %B %Y")
    dfd_mermaid = tm.dfd_mermaid or ""

    comp_by_id = {str(c.get("id")): c for c in components}
    mit_by_threat: Dict[str, List[Dict[str, Any]]] = {}
    for m in mitigations:
        mit_by_threat.setdefault(str(m.get("threat_id")), []).append(m)

    # ── Overview cards ────────────────────────────────────────────────────────
    coverage_pct = 0
    if coverage:
        non_missing = sum(1 for d in coverage if d.get("state") != "missing")
        coverage_pct = round((non_missing / len(coverage)) * 100, 1)

    overview_html = f"""
<div class="kpi-row">
  <div class="kpi"><div class="kpi-v">{len(threats)}</div><div class="kpi-l">Threats</div></div>
  <div class="kpi"><div class="kpi-v">{len(components)}</div><div class="kpi-l">Components</div></div>
  <div class="kpi"><div class="kpi-v">{len(mitigations)}</div><div class="kpi-l">Mitigations</div></div>
  <div class="kpi"><div class="kpi-v">{coverage_pct}%</div><div class="kpi-l">Coverage</div></div>
  <div class="kpi"><div class="kpi-v">{len(trust_boundaries)}</div><div class="kpi-l">Boundaries</div></div>
  <div class="kpi"><div class="kpi-v">{len(entry_points)}</div><div class="kpi-l">Entry Points</div></div>
</div>
{f'<div class="exec-summary"><strong>Executive Summary</strong><p>{_h(tm.executive_summary)}</p></div>' if tm.executive_summary else ""}
"""

    # ── Diagram tab ────────────────────────────────────────────────────────────
    diagram_html = f"""
<div class="section-label">Data Flow Diagram — {_h(methodology)}</div>
{"<div class='mermaid'>" + _h(dfd_mermaid) + "</div>" if dfd_mermaid else "<p class='muted'>No diagram generated yet.</p>"}
"""

    # ── Components tab ─────────────────────────────────────────────────────────
    threatened_ids = {str(t.get("asset_id")) for t in threats}
    comp_rows = "".join(
        f"<tr><td>{_h(c.get('id'))}</td><td>{_h(c.get('name'))}</td>"
        f"<td>{_h(c.get('type'))}</td><td><span class='zone-pill'>{_h(c.get('trust_zone'))}</span></td>"
        f"<td>{_h(c.get('criticality'))}</td>"
        f"<td>{'<span class=\"warn-pill\">No threats — review</span>' if str(c.get('id')) not in threatened_ids else '<span class=\"ok-pill\">Covered</span>'}</td>"
        f"<td>{_h(c.get('notes'))}</td></tr>"
        for c in components
    ) or "<tr><td colspan='7' class='muted'>No components.</td></tr>"
    flow_rows = "".join(
        f"<tr><td>{_h(comp_by_id.get(str(f.get('from')),{}).get('name') or f.get('from'))}</td>"
        f"<td>{_h(comp_by_id.get(str(f.get('to')),{}).get('name') or f.get('to'))}</td>"
        f"<td><span class='proto-pill'>{_h(f.get('protocol'))}</span></td><td>{_h(f.get('data'))}</td>"
        f"<td>{'<span class=\"enc-yes\">TLS</span>' if f.get('encrypted') else '<span class=\"enc-no\">PLAIN</span>'}</td>"
        f"<td>{'<span class=\"warn-pill\">⚠ Crosses boundary</span>' if f.get('trust_boundary_crossing') else ''}</td></tr>"
        for f in data_flows
    ) or "<tr><td colspan='6' class='muted'>No data flows.</td></tr>"
    components_html = f"""
<h3>Components ({len(components)})</h3>
<table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Trust Zone</th><th>Criticality</th><th>Coverage</th><th>Notes</th></tr></thead>
<tbody>{comp_rows}</tbody></table>
<h3>Data Flows ({len(data_flows)})</h3>
<table><thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Data</th><th>Encrypted</th><th>Flags</th></tr></thead>
<tbody>{flow_rows}</tbody></table>
"""

    # ── Boundaries tab ─────────────────────────────────────────────────────────
    tb_rows = "".join(
        f"<tr><td>{_h(tb.get('name'))}</td><td>{_h(tb.get('from_zone'))} → {_h(tb.get('to_zone'))}</td>"
        f"<td>{_h(tb.get('description'))}</td><td>{len(tb.get('crossed_by_flow_ids') or [])}</td></tr>"
        for tb in trust_boundaries
    ) or "<tr><td colspan='4' class='muted'>No trust boundaries.</td></tr>"
    def _ep_row(ep: Dict[str, Any]) -> str:
        exp_cls = (ep.get("exposure") or "").lower()
        auth = "Yes" if ep.get("auth_required") else "No"
        comp = _h(comp_by_id.get(str(ep.get("component_id")), {}).get("name") or ep.get("component_id"))
        return (
            f"<tr><td>{_h(ep.get('name'))}</td><td>{_h(ep.get('kind'))}</td>"
            f"<td><span class='sev-{exp_cls}'>{_h(ep.get('exposure'))}</span></td>"
            f"<td>{auth}</td><td>{comp}</td></tr>"
        )
    ep_rows = "".join(_ep_row(ep) for ep in entry_points) or "<tr><td colspan='5' class='muted'>No entry points.</td></tr>"
    cross_rows = "".join(
        f"<tr><td>{_h(comp_by_id.get(str(f.get('from')),{}).get('name') or f.get('from'))}</td>"
        f"<td>{_h(comp_by_id.get(str(f.get('to')),{}).get('name') or f.get('to'))}</td>"
        f"<td>{_h(f.get('protocol'))}</td><td>{_h(f.get('data'))}</td></tr>"
        for f in data_flows if f.get("trust_boundary_crossing")
    ) or "<tr><td colspan='4' class='muted'>No boundary-crossing flows.</td></tr>"
    boundaries_html = f"""
<h3>Trust Boundaries ({len(trust_boundaries)})</h3>
<table><thead><tr><th>Name</th><th>Zones</th><th>Description</th><th>Crossing flows</th></tr></thead>
<tbody>{tb_rows}</tbody></table>
<h3>Entry Points ({len(entry_points)})</h3>
<table><thead><tr><th>Name</th><th>Kind</th><th>Exposure</th><th>Auth required</th><th>Component</th></tr></thead>
<tbody>{ep_rows}</tbody></table>
<h3>Boundary-Crossing Flows</h3>
<table><thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Data</th></tr></thead>
<tbody>{cross_rows}</tbody></table>
"""

    # ── Threats tab ────────────────────────────────────────────────────────────
    by_comp: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats:
        by_comp.setdefault(str(t.get("asset_id")) or "(unscoped)", []).append(t)
    threat_blocks = []
    for comp_id, t_list in by_comp.items():
        comp_name = comp_by_id.get(comp_id, {}).get("name") or comp_id
        threat_blocks.append(f"<h3>{_h(comp_name)} <span class='muted'>({len(t_list)} threats)</span></h3>")
        for t in sorted(t_list, key=lambda x: x.get("priority_score", 0), reverse=True):
            sev = (t.get("severity") or "medium").lower()
            bg = _SEV_BG.get(sev, "#f1f5f9")
            fg = _SEV_FG.get(sev, "#475569")
            mits = mit_by_threat.get(str(t.get("id")), [])
            mit_li = "".join(f"<li><strong>{_h(m.get('action'))}</strong> <span class='muted'>({_h(m.get('status','open'))})</span></li>" for m in mits)
            threat_blocks.append(f"""<div class="threat-card" style="border-left:3px solid {fg}; background:{bg}20;">
  <div class="threat-meta">
    <span class="pill" style="background:{bg};color:{fg};">{sev.upper()}</span>
    <span class="pill pill-grey">{_h(t.get('category','').replace('_',' ').title())}</span>
    <span class="pill pill-blue">P{t.get('priority_score','—')}</span>
    <span class="pill {'pill-green' if t.get('is_grounded') else 'pill-red'}">{'' if t.get('is_grounded') else 'UNGROUNDED'}</span>
  </div>
  <h4>{_h(t.get('title'))}</h4>
  <p>{_h(t.get('rationale'))}</p>
  {f"<p><strong>Mitigations:</strong></p><ul>{mit_li}</ul>" if mits else ""}
</div>""")
    threats_html = "".join(threat_blocks) if threats else "<p class='muted'>No threats identified yet.</p>"

    # ── Coverage matrix tab ───────────────────────────────────────────────────
    if components and coverage:
        categories = sorted({d.get("category") for d in coverage if d.get("category")})
        by_cell = {(d.get("component_id"), d.get("category")): d for d in coverage}
        hdr_cells = "<th>Component</th>" + "".join(f"<th>{_h(c.replace('_',' ').title())}</th>" for c in categories)
        cov_rows = []
        for c in components:
            cells = [f"<td><strong>{_h(c.get('name'))}</strong></td>"]
            for cat in categories:
                d = by_cell.get((str(c.get("id")), cat))
                if d:
                    st = d.get("state", "missing")
                    b = _STATE_BG.get(st, "#f1f5f9")
                    f2 = _STATE_FG.get(st, "#475569")
                    cells.append(f"<td style='background:{b};color:{f2};font-size:11px;'>{st.replace('_',' ').title()}</td>")
                else:
                    cells.append("<td>—</td>")
            cov_rows.append("<tr>" + "".join(cells) + "</tr>")
        coverage_html = f"<table class='coverage-table'><thead><tr>{hdr_cells}</tr></thead><tbody>{''.join(cov_rows)}</tbody></table>"
    else:
        coverage_html = "<p class='muted'>No coverage data.</p>"

    # ── Mitigations tab ───────────────────────────────────────────────────────
    def _mit_row(m: Dict[str, Any]) -> str:
        ctrl = ", ".join(f"{_h(r.get('framework'))}:{_h(r.get('control_id'))}" for r in (m.get("control_refs") or []))
        return (
            f"<tr><td>{_h(m.get('threat_id'))}</td><td>{_h(m.get('action'))}</td>"
            f"<td>{_h(m.get('owner_role') or m.get('owner') or '—')}</td>"
            f"<td><span class='pill pill-grey'>{_h(m.get('status','open'))}</span></td>"
            f"<td>{ctrl}</td></tr>"
        )
    mit_rows = "".join(_mit_row(m) for m in mitigations) or "<tr><td colspan='5' class='muted'>No mitigations.</td></tr>"
    mitigations_html = f"""
<table><thead><tr><th>Threat</th><th>Action</th><th>Owner</th><th>Status</th><th>Controls</th></tr></thead>
<tbody>{mit_rows}</tbody></table>
"""

    # ── Maturity tab ──────────────────────────────────────────────────────────
    if maturity:
        mat_cards = "".join(
            f"<div class='mat-card'><div class='mat-label'>{_h(k.replace('_',' ').title())}</div>"
            f"<div class='mat-score'>{float(v):.1f}<span class='muted'>/5</span></div>"
            f"<div class='mat-bar'><div class='mat-fill' style='width:{_pct(min(1.0,float(v)/5.0))}'></div></div></div>"
            for k, v in sorted(maturity.items())
        )
        maturity_html = f"<div class='mat-grid'>{mat_cards}</div>"
    else:
        maturity_html = "<p class='muted'>No maturity data.</p>"

    # ── Detection Rules tab ───────────────────────────────────────────────────
    if sigma_rules:
        rule_blocks = "".join(
            f"<div class='rule-card'><div class='rule-title'>{_h(r.get('rule_id',''))}: {_h(r.get('description',''))}</div>"
            f"<pre class='sigma-pre'>{_h(r.get('sigma_yaml',''))}</pre></div>"
            for r in sigma_rules
        )
        detections_html = rule_blocks
    else:
        detections_html = "<p class='muted'>No detection rules generated yet. Use AI → Suggest Detection Rules.</p>"

    # ── Tab definitions ───────────────────────────────────────────────────────
    tabs = [
        ("diagram",     "Diagram",          diagram_html),
        ("components",  "Components",       components_html),
        ("boundaries",  "Boundaries",       boundaries_html),
        ("threats",     "Threats",          threats_html),
        ("coverage",    "Coverage Matrix",  coverage_html),
        ("mitigations", "Mitigations",      mitigations_html),
        ("maturity",    "Maturity",         maturity_html),
        ("detections",  "Detection Rules",  detections_html),
    ]

    tab_buttons = "".join(
        f'<button class="tab-btn" onclick="showTab(this,\'{tid}\')">{_h(tlabel)}</button>'
        for tid, tlabel, _ in tabs
    )
    tab_panels = "".join(
        f'<div id="tab-{tid}" class="tab-panel">{content}</div>'
        for tid, _, content in tabs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{_h(title)} — NexGen Cyber AI</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
  <style>
    :root {{ --blue:#1a73e8; --red:#ea4335; --green:#34a853; --orange:#ff9800; --grey:#6b7280; }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:"Segoe UI","Inter",Arial,sans-serif; background:#0f0f13; color:#e2e8f0; font-size:14px; }}
    .topbar {{ background:#1a1a2e; border-bottom:1px solid #2d2d45; padding:12px 24px; display:flex; align-items:center; gap:16px; flex-wrap:wrap; }}
    .brand {{ color:var(--blue); font-weight:700; font-size:18px; }}
    .title {{ font-weight:600; font-size:16px; color:#f1f5f9; }}
    .meta {{ color:var(--grey); font-size:12px; }}
    .kpi-row {{ display:flex; gap:12px; flex-wrap:wrap; padding:16px 24px; background:#141420; border-bottom:1px solid #2d2d45; }}
    .kpi {{ background:#1e1e30; border:1px solid #2d2d45; border-radius:8px; padding:12px 18px; min-width:100px; }}
    .kpi-v {{ font-size:22px; font-weight:700; color:var(--blue); }}
    .kpi-l {{ font-size:11px; color:var(--grey); text-transform:uppercase; letter-spacing:.5px; margin-top:2px; }}
    .exec-summary {{ padding:12px 24px; background:#141420; border-bottom:1px solid #2d2d45; color:#94a3b8; font-size:13px; line-height:1.6; }}
    .exec-summary strong {{ color:#e2e8f0; }}
    .tab-nav {{ display:flex; gap:2px; background:#141420; border-bottom:1px solid #2d2d45; padding:0 24px; overflow-x:auto; }}
    .tab-btn {{ padding:10px 18px; background:transparent; border:none; border-bottom:2px solid transparent; color:var(--grey); font-size:13px; font-weight:600; cursor:pointer; white-space:nowrap; transition:color .15s; }}
    .tab-btn:hover {{ color:#e2e8f0; }}
    .tab-btn.active {{ border-bottom-color:var(--blue); color:var(--blue); }}
    .tab-panel {{ display:none; padding:24px; }}
    .tab-panel.active {{ display:block; }}
    .section-label {{ font-size:11px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:var(--grey); margin-bottom:12px; }}
    h3 {{ font-size:14px; font-weight:700; color:#e2e8f0; margin:20px 0 8px; padding-bottom:4px; border-bottom:1px solid #2d2d45; }}
    h4 {{ font-size:13px; font-weight:700; color:#e2e8f0; margin:8px 0 4px; }}
    p {{ color:#94a3b8; line-height:1.6; margin:4px 0; }}
    ul {{ padding-left:20px; color:#94a3b8; }}
    li {{ margin:2px 0; }}
    table {{ width:100%; border-collapse:collapse; font-size:12.5px; margin:8px 0 20px; }}
    th {{ background:#1e1e30; color:#94a3b8; font-weight:600; text-align:left; padding:8px 10px; border-bottom:1px solid #2d2d45; font-size:11px; text-transform:uppercase; letter-spacing:.4px; }}
    td {{ padding:7px 10px; border-bottom:1px solid #1e1e30; color:#e2e8f0; vertical-align:top; }}
    tr:hover td {{ background:#1a1a28; }}
    .muted {{ color:var(--grey); font-size:12px; }}
    .pill {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; line-height:1.4; }}
    .pill-grey {{ background:#2d2d45; color:#94a3b8; }}
    .pill-blue {{ background:rgba(26,115,232,.2); color:var(--blue); }}
    .pill-green {{ background:rgba(52,168,83,.2); color:var(--green); }}
    .pill-red {{ background:rgba(234,67,53,.2); color:var(--red); }}
    .zone-pill {{ background:#1e293b; color:#7dd3fc; font-size:11px; padding:2px 8px; border-radius:8px; }}
    .proto-pill {{ background:#1e293b; color:#94a3b8; font-size:11px; padding:2px 8px; border-radius:8px; }}
    .enc-yes {{ color:var(--green); font-weight:700; font-size:11px; }}
    .enc-no {{ color:var(--red); font-weight:700; font-size:11px; }}
    .warn-pill {{ background:rgba(255,152,0,.15); color:var(--orange); font-size:11px; padding:2px 8px; border-radius:8px; font-weight:700; }}
    .ok-pill {{ background:rgba(52,168,83,.1); color:var(--green); font-size:11px; padding:2px 8px; border-radius:8px; font-weight:700; }}
    .sev-high,.sev-critical {{ color:var(--red); font-weight:700; }}
    .sev-medium {{ color:var(--orange); font-weight:700; }}
    .sev-low {{ color:var(--green); font-weight:700; }}
    .threat-card {{ padding:12px 14px; border-radius:6px; margin:10px 0; border-left-width:3px; border-left-style:solid; }}
    .threat-meta {{ display:flex; gap:6px; flex-wrap:wrap; margin-bottom:6px; }}
    .mat-grid {{ display:flex; flex-wrap:wrap; gap:12px; }}
    .mat-card {{ background:#1e1e30; border:1px solid #2d2d45; border-radius:8px; padding:12px 16px; min-width:160px; flex:1; }}
    .mat-label {{ font-size:11px; color:var(--grey); text-transform:uppercase; letter-spacing:.5px; }}
    .mat-score {{ font-size:24px; font-weight:700; color:var(--blue); margin:4px 0; }}
    .mat-bar {{ height:5px; background:#2d2d45; border-radius:3px; overflow:hidden; }}
    .mat-fill {{ height:100%; background:var(--blue); border-radius:3px; }}
    .coverage-table {{ font-size:11px; }}
    .coverage-table th {{ font-size:10px; }}
    .rule-card {{ background:#0d1117; border:1px solid #2d2d45; border-radius:6px; padding:14px; margin:10px 0; }}
    .rule-title {{ font-weight:700; color:#e2e8f0; font-size:12px; margin-bottom:8px; }}
    .sigma-pre {{ font-family:"Fira Code","Consolas",monospace; font-size:11px; color:#e6edf3; background:#0d1117; overflow:auto; white-space:pre; line-height:1.5; }}
    .mermaid {{ background:#1a1a2e; border-radius:8px; padding:16px; overflow:auto; }}
  </style>
</head>
<body>
  <div class="topbar">
    <span class="brand">NexGen Cyber AI</span>
    <div>
      <div class="title">{_h(title)}</div>
      <div class="meta">Client: {_h(client_name)} &nbsp;·&nbsp; {_h(methodology)} &nbsp;·&nbsp; {_h(date_str)}</div>
    </div>
  </div>
  {overview_html}
  <div class="tab-nav">
    {tab_buttons}
  </div>
  {tab_panels}
  <script>
    mermaid.initialize({{ startOnLoad: true, theme: "dark" }});
    function showTab(btn, id) {{
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-" + id).classList.add("active");
    }}
    // activate first tab
    var first = document.querySelector(".tab-btn");
    if (first) first.click();
  </script>
</body>
</html>"""
