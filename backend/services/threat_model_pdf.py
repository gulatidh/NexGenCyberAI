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
    """Self-contained HTML mirroring the portal's tab layout.

    Includes Mermaid.js (CDN) so the diagram renders in any browser.
    Enhanced with: risk scoring legend, threat actor profiles, scope &
    assumptions, regulatory traceability matrix, attack narratives,
    specific mitigation implementation details, and data classification.
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
    adversary_profiles: List[Dict[str, Any]] = tm.adversary_profiles_json or []
    metadata: Dict[str, Any] = (tm.metadata_json or {}) if isinstance(tm.metadata_json, dict) else {}

    methodology = (tm.methodology or "stride").upper()
    title = tm.name or f"Threat Model · {methodology}"
    date_str = (tm.generated_at or datetime.utcnow()).strftime("%d %B %Y")
    dfd_mermaid = tm.dfd_mermaid or ""

    comp_by_id = {str(c.get("id")): c for c in components}
    mit_by_threat: Dict[str, List[Dict[str, Any]]] = {}
    for m in mitigations:
        mit_by_threat.setdefault(str(m.get("threat_id")), []).append(m)

    # ── Overview KPI cards ─────────────────────────────────────────────────────
    coverage_pct = 0
    if coverage:
        non_missing = sum(1 for d in coverage if d.get("state") != "missing")
        coverage_pct = round((non_missing / len(coverage)) * 100, 1)

    critical_count = sum(1 for t in threats if (t.get("severity") or "").lower() == "critical")
    high_count = sum(1 for t in threats if (t.get("severity") or "").lower() == "high")

    overview_html = f"""
<div class="kpi-row">
  <div class="kpi"><div class="kpi-v" style="color:#ea4335;">{critical_count}</div><div class="kpi-l">Critical Threats</div></div>
  <div class="kpi"><div class="kpi-v" style="color:#ff9800;">{high_count}</div><div class="kpi-l">High Threats</div></div>
  <div class="kpi"><div class="kpi-v">{len(threats)}</div><div class="kpi-l">Total Threats</div></div>
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
    _DATA_CLASS_COLOR = {
        "public": "#64748b", "internal": "#0369a1", "confidential": "#d97706",
        "highly_confidential": "#b91c1c", "secret": "#7c3aed",
    }
    _BIA_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#92400e", "low": "#166534"}
    threatened_ids = {str(t.get("asset_id")) for t in threats}

    def _comp_row(c: Dict[str, Any]) -> str:
        cid = str(c.get("id") or "")
        dc = (c.get("data_classification") or "").lower()
        bia = (c.get("bia_impact") or "").lower()
        bia_j = c.get("bia_justification") or ""
        dc_style = f"color:{_DATA_CLASS_COLOR.get(dc,'#64748b')};font-weight:700;font-size:11px;"
        bia_style = f"color:{_BIA_COLOR.get(bia,'#64748b')};font-weight:700;font-size:11px;"
        cov = ('<span class="warn-pill">No threats — review</span>'
               if cid not in threatened_ids else '<span class="ok-pill">Covered</span>')
        env_dc = " · ".join(x for x in [c.get("environment", ""), c.get("datacenter", "")] if x)
        return (
            f"<tr><td>{_h(c.get('name'))}</td>"
            f"<td>{_h(c.get('type'))}<br/><span class='muted'>{_h(env_dc)}</span></td>"
            f"<td><span class='zone-pill'>{_h(c.get('trust_zone'))}</span></td>"
            f"<td>{_h(c.get('criticality'))}</td>"
            f"<td><span style='{dc_style}'>{_h(dc.replace('_',' ').title() or '—')}</span></td>"
            f"<td><span style='{bia_style}'>{_h(bia.upper() or '—')}</span>"
            f"{'<br/><span class=\"muted\" style=\"font-size:10px;\">' + _h(bia_j[:80]) + '</span>' if bia_j else ''}</td>"
            f"<td>{cov}</td>"
            f"<td>{_h(c.get('notes'))}</td></tr>"
        )

    comp_rows = "".join(_comp_row(c) for c in components) or "<tr><td colspan='8' class='muted'>No components.</td></tr>"

    _DATA_LABEL_STYLE = {
        "pii": "color:#b91c1c;font-weight:700;", "financial": "color:#c2410c;font-weight:700;",
        "credentials": "color:#7c3aed;font-weight:700;", "audit_logs": "color:#0369a1;font-weight:700;",
        "session_tokens": "color:#7c3aed;font-weight:700;", "highly_confidential": "color:#b91c1c;font-weight:700;",
    }

    def _flow_row(f: Dict[str, Any]) -> str:
        data_label = _h(f.get("data") or "—")
        data_style = _DATA_LABEL_STYLE.get((f.get("data") or "").lower(), "")
        boundary_flag = '<span class="warn-pill">⚠ Crosses boundary</span>' if f.get("trust_boundary_crossing") else ""
        atk_flag = '<span class="pill" style="background:#fee2e2;color:#b91c1c;font-size:10px;border:1px solid #fca5a5;">Attack vector</span>' if f.get("is_attack_vector") else ""
        return (
            f"<tr>"
            f"<td>{_h(comp_by_id.get(str(f.get('from')),{{}}).get('name') or f.get('from'))}</td>"
            f"<td>{_h(comp_by_id.get(str(f.get('to')),{{}}).get('name') or f.get('to'))}</td>"
            f"<td><span class='proto-pill'>{_h(f.get('protocol'))}</span> <span class='muted'>{_h(f.get('port') or '')}</span></td>"
            f"<td><span style='{data_style}'>{data_label}</span></td>"
            f"<td>{'<span class=\"enc-yes\">TLS</span>' if f.get('encrypted') else '<span class=\"enc-no\">PLAIN</span>'}</td>"
            f"<td>{boundary_flag}{atk_flag}</td></tr>"
        )

    flow_rows = "".join(_flow_row(f) for f in data_flows) or "<tr><td colspan='6' class='muted'>No data flows.</td></tr>"

    components_html = f"""
<h3>Components ({len(components)})</h3>
<p class="muted" style="margin-bottom:8px;">Data classification: <span style="color:#64748b;font-weight:700;">Public</span> · <span style="color:#0369a1;font-weight:700;">Internal</span> · <span style="color:#d97706;font-weight:700;">Confidential</span> · <span style="color:#b91c1c;font-weight:700;">Highly Confidential</span> · <span style="color:#7c3aed;font-weight:700;">Secret</span></p>
<table><thead><tr><th>Name</th><th>Type / Environment</th><th>Trust Zone</th><th>Criticality</th><th>Data Classification</th><th>BIA Impact</th><th>Coverage</th><th>Notes</th></tr></thead>
<tbody>{comp_rows}</tbody></table>
<h3>Data Flows ({len(data_flows)})</h3>
<table><thead><tr><th>From</th><th>To</th><th>Protocol / Port</th><th>Data</th><th>Encrypted</th><th>Flags</th></tr></thead>
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
        f"<tr><td>{_h(comp_by_id.get(str(f.get('from')),{{}}).get('name') or f.get('from'))}</td>"
        f"<td>{_h(comp_by_id.get(str(f.get('to')),{{}}).get('name') or f.get('to'))}</td>"
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

    # ── Threats tab — with scoring legend, ATT&CK, attack narrative, blast radius ──
    _SEV_WEIGHT = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
    _CRIT_WEIGHT = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}
    scoring_legend = """
<div class="info-box" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 18px;margin-bottom:16px;">
  <div class="section-label" style="margin-bottom:8px;">Risk Scoring Model — DREAD-derived Priority Formula</div>
  <p style="margin-bottom:6px;">Priority Score (P) = <strong>Severity Weight × Likelihood (1-10) × Impact (1-10) × Asset Criticality Weight</strong></p>
  <div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:8px;">
    <div><div class="section-label">Severity Weight</div>
      <table style="margin:4px 0;"><tr><td style="color:#b91c1c;font-weight:700;">Critical</td><td style="padding-left:12px;">× 3.0</td></tr>
      <tr><td style="color:#c2410c;font-weight:700;">High</td><td style="padding-left:12px;">× 2.0</td></tr>
      <tr><td style="color:#92400e;font-weight:700;">Medium</td><td style="padding-left:12px;">× 1.0</td></tr>
      <tr><td style="color:#166534;font-weight:700;">Low</td><td style="padding-left:12px;">× 0.5</td></tr></table></div>
    <div><div class="section-label">Asset Criticality Weight</div>
      <table style="margin:4px 0;"><tr><td style="color:#b91c1c;font-weight:700;">Critical</td><td style="padding-left:12px;">× 2.0</td></tr>
      <tr><td style="color:#c2410c;font-weight:700;">High</td><td style="padding-left:12px;">× 1.5</td></tr>
      <tr><td style="color:#92400e;font-weight:700;">Medium</td><td style="padding-left:12px;">× 1.0</td></tr>
      <tr><td style="color:#166534;font-weight:700;">Low</td><td style="padding-left:12px;">× 0.5</td></tr></table></div>
    <div><div class="section-label">Risk Register Score</div><p style="margin-top:6px;">= Likelihood × Impact ÷ 10</p>
      <p style="margin-top:4px;color:#64748b;font-size:11px;">Used in the risk register. Max score = 10 (L=10, I=10).</p></div>
    <div><div class="section-label">Grounding</div>
      <p style="margin-top:6px;"><span class="pill pill-red">UNGROUNDED</span> = no CVE, finding, or ATT&amp;CK evidence cited.</p>
      <p>Ungrounded threats are retained but demoted — treat as hypothetical until evidence is attached.</p></div>
  </div>
</div>"""

    by_comp: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats:
        by_comp.setdefault(str(t.get("asset_id")) or "(unscoped)", []).append(t)
    threat_blocks = [scoring_legend]
    for comp_id, t_list in by_comp.items():
        comp_name = comp_by_id.get(comp_id, {}).get("name") or comp_id
        threat_blocks.append(f"<h3>{_h(comp_name)} <span class='muted'>({len(t_list)} threats)</span></h3>")
        for t in sorted(t_list, key=lambda x: x.get("priority_score", 0), reverse=True):
            sev = (t.get("severity") or "medium").lower()
            bg = {"critical": "#fee2e2", "high": "#ffedd5", "medium": "#fef3c7", "low": "#dcfce7"}.get(sev, "#f1f5f9")
            fg = {"critical": "#991b1b", "high": "#9a3412", "medium": "#92400e", "low": "#166534"}.get(sev, "#475569")
            mits = mit_by_threat.get(str(t.get("id")), [])
            mit_li = "".join(
                f"<li><strong>{_h(m.get('action'))}</strong> <span class='muted'>({_h(m.get('status','open'))})</span></li>"
                for m in mits
            )
            li_val = int(t.get("likelihood") or 0)
            im_val = int(t.get("impact") or 0)
            ps = t.get("priority_score")
            score_detail = (f"L{li_val} × I{im_val} = {li_val*im_val}" if li_val and im_val else "—")
            techniques = t.get("attack_techniques") or []
            capecs = t.get("capec_refs") or []
            cwes = t.get("cwe_refs") or []
            blast = t.get("blast_radius") or []
            blast_names = [comp_by_id.get(bid, {}).get("name") or bid for bid in blast]
            narrative = t.get("attack_narrative") or ""
            tech_pills = "".join(
                f"<span class='pill' style='background:#f1f5f9;color:#475569;font-size:10px;margin:1px;border:1px solid #e2e8f0;'>{_h(tech)}</span>"
                for tech in (techniques + capecs + cwes)[:8]
            )
            blast_text = (
                "<p style='margin-top:6px;'><strong>Blast radius:</strong> " +
                " → ".join(f"<span class='zone-pill'>{_h(n)}</span>" for n in blast_names) + "</p>"
                if blast_names else ""
            )
            narrative_block = (
                f"<div style='margin-top:8px;padding:8px 10px;background:#f1f5f9;border-radius:4px;font-size:12px;border-left:3px solid #cbd5e1;'>"
                f"<div class='section-label' style='margin-bottom:4px;'>Attack Narrative</div>"
                f"<p style='color:#334155;'>{_h(narrative)}</p></div>"
                if narrative else ""
            )
            threat_blocks.append(f"""<div class="threat-card" style="border-left:3px solid {fg}; background:{bg};">
  <div class="threat-meta">
    <span class="pill" style="background:{bg};color:{fg};">{sev.upper()}</span>
    <span class="pill pill-grey">{_h((t.get('category') or '').replace('_',' ').title())}</span>
    <span class="pill pill-blue" title="Priority Score = Severity Weight × Likelihood × Impact × Asset Criticality Weight">P{_h(str(ps or '—'))}</span>
    <span class="pill pill-grey" title="Likelihood × Impact">{_h(score_detail)}</span>
    <span class="pill {'pill-green' if t.get('is_grounded') else 'pill-red'}">{'' if t.get('is_grounded') else 'UNGROUNDED'}</span>
    {tech_pills}
  </div>
  <h4>{_h(t.get('title'))}</h4>
  <p>{_h(t.get('rationale'))}</p>
  {narrative_block}
  {blast_text}
  {f"<p style='margin-top:6px;'><strong>Mitigations:</strong></p><ul>{mit_li}</ul>" if mits else ""}
</div>""")
    threats_html = "".join(threat_blocks) if threats else "<p class='muted'>No threats identified yet.</p>"

    # ── Coverage matrix tab ────────────────────────────────────────────────────
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

    # ── Mitigations tab — with implementation detail, architecture, regulatory refs ──
    _ARCH_ICONS = {
        "ztna": "🔐 ZTNA", "identity_aware_proxy": "🔐 Identity-Aware Proxy",
        "network_segmentation": "🔲 Network Segmentation", "pam": "🗝 PAM",
        "mfa": "📱 MFA", "tls": "🔒 TLS Encryption",
        "monitoring": "📊 Monitoring / SIEM", "patching": "🩹 Patch Management",
        "waf": "🛡 WAF", "dlp": "📋 DLP", "siem": "📊 SIEM",
        "data_encryption": "🔒 Data Encryption", "least_privilege": "🎯 Least Privilege",
    }

    def _mit_row_portal(m: Dict[str, Any]) -> str:
        ctrl = ", ".join(
            f"{_h(r.get('framework'))}:{_h(r.get('control_id'))}" for r in (m.get("control_refs") or [])
        )
        reg_refs = m.get("regulatory_refs") or []
        reg_text = " · ".join(
            f"{_h(r.get('framework','').upper())} §{_h(r.get('section',''))}" for r in reg_refs
        ) if reg_refs else ""
        arch = (m.get("architecture_approach") or "").lower()
        arch_label = _ARCH_ICONS.get(arch, _h(arch.replace("_", " ").title()) if arch else "")
        detail = m.get("implementation_detail") or ""
        return (
            f"<tr><td style='color:#1d4ed8;font-weight:700;font-family:monospace;'>{_h(m.get('threat_id'))}</td>"
            f"<td><strong>{_h(m.get('action'))}</strong>"
            f"{'<div style=\"margin-top:6px;color:#475569;font-size:11.5px;\">' + _h(detail) + '</div>' if detail else ''}"
            f"{'<div style=\"margin-top:4px;\"><span class=\"pill pill-blue\" style=\"font-size:10px;\">' + arch_label + '</span></div>' if arch_label else ''}"
            f"</td>"
            f"<td>{_h(m.get('owner_role') or m.get('owner') or '—')}</td>"
            f"<td><span class='pill pill-grey'>{_h(m.get('status','open'))}</span></td>"
            f"<td style='font-size:11px;'>{ctrl}"
            f"{'<br/><span style=\"color:#c2410c;font-size:11px;\">' + _h(reg_text) + '</span>' if reg_text else ''}"
            f"</td></tr>"
        )

    mit_rows = "".join(_mit_row_portal(m) for m in mitigations) or "<tr><td colspan='5' class='muted'>No mitigations.</td></tr>"
    mitigations_html = f"""
<p class="muted" style="margin-bottom:12px;">Each mitigation includes specific implementation guidance and references to applicable regulatory controls (NIST 800-53, MAS TRM, GCC IM8, ISO 27001, PCI DSS).</p>
<table><thead><tr><th>Threat</th><th>Action &amp; Implementation Detail</th><th>Owner</th><th>Status</th><th>Controls / Regulatory</th></tr></thead>
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

    # ── Threat Actors (Adversary Profiles) tab ────────────────────────────────
    _SOPH_COLOR = {"high": "#b91c1c", "medium": "#c2410c", "low": "#166534"}
    _MOTIV_LABEL = {
        "espionage": "State / Corporate Espionage", "financial": "Financial Gain",
        "disruption": "Service Disruption / Sabotage", "activism": "Hacktivism",
        "sabotage": "Insider Sabotage", "insider_grievance": "Insider Grievance",
        "unknown": "Unknown",
    }
    if adversary_profiles:
        actor_blocks = []
        for ap in adversary_profiles:
            soph = (ap.get("sophistication") or "medium").lower()
            soph_color = _SOPH_COLOR.get(soph, "#64748b")
            motiv_raw = (ap.get("motivation") or "unknown").lower()
            motiv_label = _MOTIV_LABEL.get(motiv_raw, motiv_raw.replace("_", " ").title())
            techniques = ap.get("likely_techniques") or []
            tech_pills = "".join(
                f"<span class='pill' style='background:#dbeafe;color:#1d4ed8;font-size:10px;margin:1px;border:1px solid #bfdbfe;'>ATT&amp;CK {_h(t)}</span>"
                for t in techniques[:10]
            )
            targeted = ap.get("targeted_assets") or []
            target_names = [comp_by_id.get(tid, {}).get("name") or tid for tid in targeted]
            threat_ids = ap.get("threat_ids") or []
            actor_blocks.append(f"""
<div class="threat-card" style="border-left:3px solid {soph_color}; background:#f8fafc; margin:12px 0;">
  <div class="threat-meta">
    <span class="pill" style="background:#f1f5f9;color:{soph_color};font-weight:700;border:1px solid #e2e8f0;">{soph.upper()} SOPHISTICATION</span>
    <span class="pill pill-grey">{_h((ap.get('type') or '').replace('_',' ').title())}</span>
    <span class="pill pill-blue">L{_h(str(ap.get('likelihood','—')))}/10</span>
  </div>
  <h4>{_h(ap.get('name'))}</h4>
  <p><strong>Motivation:</strong> {_h(motiv_label)}</p>
  <p style="margin-top:4px;">{_h(ap.get('rationale') or '')}</p>
  {('<div style="margin-top:8px;"><div class="section-label" style="margin-bottom:4px;">MITRE ATT&CK Techniques</div>' + tech_pills + '</div>') if tech_pills else ''}
  {('<p style="margin-top:6px;"><strong>Targeted assets:</strong> ' + ', '.join(f'<span class="zone-pill">{_h(n)}</span>' for n in target_names) + '</p>') if target_names else ''}
  {('<p style="margin-top:4px;"><strong>Associated threats:</strong> ' + ', '.join(f'<span class="pill pill-blue">{_h(tid)}</span>' for tid in threat_ids) + '</p>') if threat_ids else ''}
</div>""")
        actors_html = "".join(actor_blocks)
    else:
        actors_html = "<p class='muted'>No adversary profiles generated. Re-generate the threat model to include actor profiles.</p>"

    # ── Scope & Assumptions tab ───────────────────────────────────────────────
    scope_stmt = metadata.get("scope_statement") or ""
    out_of_scope = metadata.get("out_of_scope") or []
    assumptions = metadata.get("assumptions") or []
    reg_fws = metadata.get("regulatory_frameworks_applicable") or []

    in_scope_items = []
    non_actor_comps = [c for c in components if not c.get("is_threat_actor")]
    for c in non_actor_comps[:20]:
        env = c.get("environment") or ""
        dc = c.get("datacenter") or ""
        sub = " · ".join(x for x in [env, dc] if x)
        in_scope_items.append(f"<li><strong>{_h(c.get('name'))}</strong> [{_h(c.get('trust_zone'))}]"
                              f"{(' — ' + _h(sub)) if sub else ''}</li>")
    for tb in trust_boundaries[:8]:
        in_scope_items.append(f"<li>Trust boundary: <strong>{_h(tb.get('name'))}</strong></li>")

    oos_items = "".join(f"<li>{_h(x)}</li>" for x in out_of_scope) if out_of_scope else (
        "<li>Physical security of data center facilities</li>"
        "<li>Third-party SaaS supply chain and vendor security posture</li>"
        "<li>End-user device security and endpoint management</li>"
        "<li>Network infrastructure owned by ISPs or cloud providers (shared responsibility boundary)</li>"
    )
    assump_items = "".join(f"<li>{_h(x)}</li>" for x in assumptions) if assumptions else (
        "<li>Network access control lists (ACLs) and firewall rules are correctly implemented as described</li>"
        "<li>TLS certificates are valid, properly managed, and renewed before expiry</li>"
        "<li>A patch management process exists; current patch cadence and coverage are unverified</li>"
        "<li>Authentication controls described are actively enforced (not configured but bypassed)</li>"
    )
    reg_fw_items = "".join(
        f"<li><span class='pill pill-blue'>{_h(fw.upper().replace('_', ' '))}</span></li>" for fw in reg_fws
    ) if reg_fws else (
        "<li><span class='pill pill-blue'>NIST 800-53</span></li>"
        "<li><span class='pill pill-blue'>ISO 27001</span></li>"
    )

    scope_html = f"""
<div class="info-box" style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:16px;margin-bottom:16px;">
  <div class="section-label">Scope Statement</div>
  <p style="margin-top:6px;">{_h(scope_stmt) if scope_stmt else 'This threat model covers the identified architectural components, trust boundaries, and data flows within the system boundary as described.'}</p>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;flex-wrap:wrap;">
  <div>
    <h3>In Scope</h3>
    <ul style="margin-top:8px;line-height:2;">{chr(10).join(in_scope_items) or '<li>No components recorded.</li>'}</ul>
  </div>
  <div>
    <h3>Out of Scope</h3>
    <ul style="margin-top:8px;line-height:2;">{oos_items}</ul>
  </div>
</div>
<h3 style="margin-top:20px;">Modelling Assumptions</h3>
<ul style="margin-top:8px;line-height:2;">{assump_items}</ul>
<h3 style="margin-top:20px;">Applicable Regulatory Frameworks</h3>
<ul style="margin-top:8px;list-style:none;padding:0;display:flex;gap:8px;flex-wrap:wrap;">{reg_fw_items}</ul>
"""

    # ── Regulatory Traceability Matrix tab ────────────────────────────────────
    all_frameworks: List[str] = []
    fw_threat_map: Dict[str, Dict[str, List[str]]] = {}
    for m in mitigations:
        t_id = _h(m.get("threat_id") or "")
        for r in (m.get("control_refs") or []):
            fw = (r.get("framework") or "").lower()
            ctrl = r.get("control_id") or ""
            if fw and ctrl:
                if fw not in all_frameworks:
                    all_frameworks.append(fw)
                fw_threat_map.setdefault(fw, {}).setdefault(ctrl, []).append(t_id)
        for r in (m.get("regulatory_refs") or []):
            fw = (r.get("framework") or "").lower()
            sect = r.get("section") or ""
            req = r.get("requirement") or ""
            if fw and (sect or req):
                if fw not in all_frameworks:
                    all_frameworks.append(fw)
                key = sect or req
                fw_threat_map.setdefault(fw, {}).setdefault(key, []).append(t_id)

    if fw_threat_map:
        reg_blocks = []
        for fw in all_frameworks:
            ctrl_map = fw_threat_map.get(fw, {})
            ctrl_rows = "".join(
                f"<tr><td style='font-family:monospace;color:#1d4ed8;font-weight:700;'>{_h(ctrl)}</td>"
                f"<td>{' '.join('<span class=\"pill pill-blue\" style=\"font-size:10px;\">' + tid + '</span>' for tid in tids)}</td></tr>"
                for ctrl, tids in sorted(ctrl_map.items())
            )
            reg_blocks.append(
                f"<h3>{_h(fw.upper().replace('_',' '))}</h3>"
                f"<table><thead><tr><th>Control / Section</th><th>Addressed by Threats</th></tr></thead>"
                f"<tbody>{ctrl_rows}</tbody></table>"
            )
        regulatory_html = "".join(reg_blocks)
    else:
        regulatory_html = (
            "<p class='muted'>No regulatory control references found. Re-generate the threat model — "
            "mitigations now include MAS TRM, GCC IM8, ISO 27001, and NIST 800-53 references automatically.</p>"
        )

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
        ("diagram",     "Diagram",              diagram_html),
        ("components",  "Components",           components_html),
        ("boundaries",  "Boundaries",           boundaries_html),
        ("threats",     "Threats",              threats_html),
        ("actors",      "Threat Actors",        actors_html),
        ("scope",       "Scope & Assumptions",  scope_html),
        ("coverage",    "Coverage Matrix",      coverage_html),
        ("mitigations", "Mitigations",          mitigations_html),
        ("regulatory",  "Regulatory Traceability", regulatory_html),
        ("maturity",    "Maturity",             maturity_html),
        ("detections",  "Detection Rules",      detections_html),
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
    :root {{ --blue:#1a73e8; --red:#c62828; --green:#2e7d32; --orange:#e65100; --grey:#64748b; }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:"Segoe UI","Inter",Arial,sans-serif; background:#ffffff; color:#0f172a; font-size:14px; }}
    .topbar {{ background:#1a73e8; padding:12px 24px; display:flex; align-items:center; gap:16px; flex-wrap:wrap; }}
    .brand {{ color:#ffffff; font-weight:700; font-size:18px; opacity:.9; }}
    .title {{ font-weight:600; font-size:16px; color:#ffffff; }}
    .meta {{ color:rgba(255,255,255,.75); font-size:12px; }}
    .kpi-row {{ display:flex; gap:12px; flex-wrap:wrap; padding:16px 24px; background:#f8fafc; border-bottom:1px solid #e2e8f0; }}
    .kpi {{ background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; padding:12px 18px; min-width:100px; box-shadow:0 1px 3px rgba(0,0,0,.06); }}
    .kpi-v {{ font-size:22px; font-weight:700; color:var(--blue); }}
    .kpi-l {{ font-size:11px; color:var(--grey); text-transform:uppercase; letter-spacing:.5px; margin-top:2px; }}
    .exec-summary {{ padding:12px 24px; background:#f0f9ff; border-bottom:1px solid #bae6fd; color:#334155; font-size:13px; line-height:1.6; }}
    .exec-summary strong {{ color:#0f172a; }}
    .tab-nav {{ display:flex; gap:2px; background:#f8fafc; border-bottom:2px solid #e2e8f0; padding:0 24px; overflow-x:auto; }}
    .tab-btn {{ padding:10px 18px; background:transparent; border:none; border-bottom:2px solid transparent; margin-bottom:-2px; color:var(--grey); font-size:13px; font-weight:600; cursor:pointer; white-space:nowrap; transition:color .15s; }}
    .tab-btn:hover {{ color:#0f172a; }}
    .tab-btn.active {{ border-bottom-color:var(--blue); color:var(--blue); }}
    .tab-panel {{ display:none; padding:24px; }}
    .tab-panel.active {{ display:block; }}
    .section-label {{ font-size:11px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:var(--grey); margin-bottom:12px; }}
    h3 {{ font-size:14px; font-weight:700; color:#0f172a; margin:20px 0 8px; padding-bottom:4px; border-bottom:2px solid #e2e8f0; }}
    h4 {{ font-size:13px; font-weight:700; color:#0f172a; margin:8px 0 4px; }}
    p {{ color:#334155; line-height:1.6; margin:4px 0; }}
    ul {{ padding-left:20px; color:#334155; }}
    li {{ margin:2px 0; }}
    table {{ width:100%; border-collapse:collapse; font-size:12.5px; margin:8px 0 20px; }}
    th {{ background:#f1f5f9; color:#475569; font-weight:700; text-align:left; padding:8px 10px; border-bottom:2px solid #e2e8f0; font-size:11px; text-transform:uppercase; letter-spacing:.4px; }}
    td {{ padding:7px 10px; border-bottom:1px solid #f1f5f9; color:#1e293b; vertical-align:top; }}
    tr:hover td {{ background:#f8fafc; }}
    .muted {{ color:var(--grey); font-size:12px; }}
    .pill {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; line-height:1.4; }}
    .pill-grey {{ background:#e2e8f0; color:#475569; }}
    .pill-blue {{ background:#dbeafe; color:#1d4ed8; }}
    .pill-green {{ background:#dcfce7; color:#166534; }}
    .pill-red {{ background:#fee2e2; color:#991b1b; }}
    .zone-pill {{ background:#e0f2fe; color:#0369a1; font-size:11px; padding:2px 8px; border-radius:8px; font-weight:600; }}
    .proto-pill {{ background:#f1f5f9; color:#475569; font-size:11px; padding:2px 8px; border-radius:8px; border:1px solid #e2e8f0; }}
    .enc-yes {{ color:#166534; font-weight:700; font-size:11px; }}
    .enc-no {{ color:#991b1b; font-weight:700; font-size:11px; }}
    .warn-pill {{ background:#fff7ed; color:#c2410c; font-size:11px; padding:2px 8px; border-radius:8px; font-weight:700; border:1px solid #fed7aa; }}
    .ok-pill {{ background:#f0fdf4; color:#166534; font-size:11px; padding:2px 8px; border-radius:8px; font-weight:700; border:1px solid #bbf7d0; }}
    .sev-high,.sev-critical {{ color:#991b1b; font-weight:700; }}
    .sev-medium {{ color:#c2410c; font-weight:700; }}
    .sev-low {{ color:#166534; font-weight:700; }}
    .threat-card {{ padding:12px 14px; border-radius:6px; margin:10px 0; border-left-width:3px; border-left-style:solid; background:#fafafa; }}
    .threat-meta {{ display:flex; gap:6px; flex-wrap:wrap; margin-bottom:6px; }}
    .mat-grid {{ display:flex; flex-wrap:wrap; gap:12px; }}
    .mat-card {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:12px 16px; min-width:160px; flex:1; }}
    .mat-label {{ font-size:11px; color:var(--grey); text-transform:uppercase; letter-spacing:.5px; }}
    .mat-score {{ font-size:24px; font-weight:700; color:var(--blue); margin:4px 0; }}
    .mat-bar {{ height:5px; background:#e2e8f0; border-radius:3px; overflow:hidden; }}
    .mat-fill {{ height:100%; background:var(--blue); border-radius:3px; }}
    .coverage-table {{ font-size:11px; }}
    .coverage-table th {{ font-size:10px; }}
    .rule-card {{ background:#1e293b; border:1px solid #334155; border-radius:6px; padding:14px; margin:10px 0; }}
    .rule-title {{ font-weight:700; color:#f1f5f9; font-size:12px; margin-bottom:8px; }}
    .sigma-pre {{ font-family:"Fira Code","Consolas",monospace; font-size:11px; color:#e2e8f0; background:#0f172a; overflow:auto; white-space:pre; line-height:1.5; padding:10px; border-radius:4px; margin-top:4px; }}
    .mermaid {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:16px; overflow:auto; }}
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
    mermaid.initialize({{ startOnLoad: true, theme: "default" }});
    function showTab(btn, id) {{
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-" + id).classList.add("active");
    }}
    var first = document.querySelector(".tab-btn");
    if (first) first.click();
  </script>
</body>
</html>"""
