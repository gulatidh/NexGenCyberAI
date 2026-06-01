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
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from api.models.models import ThreatModel


def _h(s: Any) -> str:
    """HTML-escape."""
    return html_lib.escape(str(s) if s is not None else "")


def _pct(v: float) -> str:
    return f"{round(v * 100):.0f}%"


_SEV_BG = {"critical": "#fee2e2", "high": "#ffedd5", "medium": "#fef3c7", "low": "#dcfce7"}
_SEV_FG = {"critical": "#991b1b", "high": "#9a3412", "medium": "#92400e", "low": "#166534"}
_STATE_BG = {"threat": "#fee2e2", "considered": "#e0e7ff", "not_applicable": "#f1f5f9", "missing": "#fef3c7"}
_STATE_FG = {"threat": "#991b1b", "considered": "#3730a3", "not_applicable": "#475569", "missing": "#92400e"}


def render_threat_model_html(tm: ThreatModel, *, client_name: str = "Unknown Client") -> str:
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

    # ── Sections ────────────────────────────────────────────────────────────
    cover = _cover(title, client_name, methodology, date_str, threat_count, component_count, mitigation_count, coverage_pct, grounded)
    exec_summary = _exec_summary(tm.executive_summary or "")
    completeness = _completeness_section(components, data_flows, trust_boundaries, entry_points)
    matrix = _coverage_matrix(components, coverage, threats)
    maturity_section = _maturity_section(maturity)
    threats_section = _threats_section(threats, mitigations, comp_by_id)
    mit_table = _mitigations_table(mitigations)
    signoff = _signoff()

    body = "\n".join([
        cover,
        exec_summary,
        completeness,
        matrix,
        maturity_section,
        threats_section,
        mit_table,
        signoff,
    ])

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
        f"<td>{_h(f.get('data'))}</td><td>{'Yes' if f.get('encrypted') else 'No'}</td><td>{_h(f.get('notes'))}</td></tr>"
        for f in data_flows
    )
    tb_rows = "\n".join(
        f"<tr><td>{_h(t.get('name'))}</td><td>{_h(t.get('from_zone'))} → {_h(t.get('to_zone'))}</td><td>{_h(t.get('description'))}</td></tr>"
        for t in trust_boundaries
    ) or "<tr><td colspan='3' class='muted'>(no trust boundaries enumerated)</td></tr>"
    ep_rows = "\n".join(
        f"<tr><td>{_h(e.get('name'))}</td><td>{_h(e.get('kind'))}</td><td>{_h(e.get('exposure'))}</td>"
        f"<td>{'Yes' if e.get('auth_required') else 'No'}</td><td>{_h(e.get('component_id'))}</td></tr>"
        for e in entry_points
    ) or "<tr><td colspan='5' class='muted'>(no entry points enumerated)</td></tr>"
    return f"""<section class="section">
  <h2>2. Architecture &amp; Completeness</h2>
  <h3>Components ({len(components)})</h3>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Trust zone</th><th>Criticality</th><th>Notes</th></tr></thead>
    <tbody>{comp_rows or "<tr><td colspan='6' class='muted'>(no components)</td></tr>"}</tbody>
  </table>
  <h3>Data Flows ({len(data_flows)})</h3>
  <table>
    <thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Data</th><th>Encrypted</th><th>Notes</th></tr></thead>
    <tbody>{flow_rows or "<tr><td colspan='6' class='muted'>(no data flows)</td></tr>"}</tbody>
  </table>
  <h3>Trust Boundaries ({len(trust_boundaries)})</h3>
  <table>
    <thead><tr><th>Name</th><th>Zones</th><th>Description</th></tr></thead>
    <tbody>{tb_rows}</tbody>
  </table>
  <h3>Entry Points ({len(entry_points)})</h3>
  <table>
    <thead><tr><th>Name</th><th>Kind</th><th>Exposure</th><th>Auth required</th><th>Component</th></tr></thead>
    <tbody>{ep_rows}</tbody>
  </table>
</section>"""


def _coverage_matrix(components: List[Dict[str, Any]], coverage: List[Dict[str, Any]], threats: List[Dict[str, Any]]) -> str:
    if not components or not coverage:
        return ""
    categories = sorted({d.get("category") for d in coverage if d.get("category")})
    # Build a grid: rows = components, cols = categories
    by_cell = {}
    for d in coverage:
        by_cell[(d.get("component_id"), d.get("category"))] = d
    n_cols = len(categories) + 1  # +1 for the component name column
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
  <h2>3. STRIDE Coverage Matrix</h2>
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
  <h2>4. Maturity by Category</h2>
  <p class="muted">Score 0-5 per category, derived from threat status, detection coverage, evidence quality, and unmitigated critical/high count.</p>
  <div class="maturity-radar">{''.join(cards)}</div>
</section>"""


def _threats_section(threats: List[Dict[str, Any]], mitigations: List[Dict[str, Any]], comp_by_id: Dict[str, Dict[str, Any]]) -> str:
    if not threats:
        return ""
    # Group threats by component
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
  <h2>5. Threats by Component</h2>
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
  <h2>6. Mitigation Roadmap</h2>
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
