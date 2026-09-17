"""
Self-contained HTML VAPT report generator.
Produces a single .html file with no external dependencies.
Layout: fixed sidebar + scrollable content panel.
Each finding gets its own page; sub-tabs per finding.
"""
from __future__ import annotations

import html as _html_lib
import json
import math
from datetime import datetime, timezone
from typing import Dict, List

_SEV_ORDER = ["critical", "high", "medium", "low", "informational", "info"]
_SEV_BG = {
    "critical": "#C62828", "high": "#E64A19", "medium": "#F9A825",
    "low": "#2E7D32", "informational": "#1565C0", "info": "#1565C0",
}
_SEV_FG = {
    "critical": "#fff", "high": "#fff", "medium": "#1a1a1a",
    "low": "#fff", "informational": "#fff", "info": "#fff",
}
_SEV_LIGHT = {
    "critical": "#fdecea", "high": "#fbe9e7", "medium": "#fffde7",
    "low": "#e8f5e9", "informational": "#e3f2fd", "info": "#e3f2fd",
}
_SEV_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "informational": "INFO", "info": "INFO",
}
_SEV_DOT = {
    "critical": "●", "high": "▲", "medium": "◆", "low": "▸", "info": "○",
}


def _h(s) -> str:
    if s is None or str(s).strip() == "":
        return "&#8212;"
    return _html_lib.escape(str(s))


def _sev_norm(s: str) -> str:
    s = (s or "info").lower()
    return "info" if s == "informational" else s


def _sort_key(f: Dict) -> int:
    s = _sev_norm(f.get("severity", "info"))
    try:
        return _SEV_ORDER.index(s)
    except ValueError:
        return 99


def _donut_arc(cx: float, cy: float, r: float, start_deg: float, end_deg: float, color: str) -> str:
    start_rad = math.radians(start_deg - 90)
    end_rad = math.radians(end_deg - 90)
    x1 = cx + r * math.cos(start_rad)
    y1 = cy + r * math.sin(start_rad)
    x2 = cx + r * math.cos(end_rad)
    y2 = cy + r * math.sin(end_rad)
    large_arc = 1 if (end_deg - start_deg) > 180 else 0
    return (f'<path d="M {x1:.2f} {y1:.2f} A {r} {r} 0 {large_arc} 1 {x2:.2f} {y2:.2f}" '
            f'fill="none" stroke="{color}" stroke-width="22" stroke-linecap="butt"/>')


def _build_donut(sev_counts: Dict[str, int], total: int) -> str:
    if total == 0:
        return '<svg width="200" height="200" viewBox="0 0 200 200"><circle cx="100" cy="100" r="80" fill="none" stroke="#e0e0e0" stroke-width="22"/><text x="100" y="108" text-anchor="middle" font-size="24" fill="#9e9e9e">0</text></svg>'
    arcs = []
    angle = 0.0
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        cnt = sev_counts.get(sev, 0)
        if cnt == 0:
            continue
        sweep = 360.0 * cnt / total
        end_angle = angle + sweep
        # avoid full-circle arc (degenerate SVG path)
        if sweep >= 359.9:
            end_angle = angle + 359.9
        arcs.append(_donut_arc(100, 100, 80, angle, end_angle, _SEV_BG.get(sev, "#9e9e9e")))
        angle = end_angle
    inner = "\n".join(arcs)
    return (f'<svg width="200" height="200" viewBox="0 0 200 200">{inner}'
            f'<text x="100" y="100" text-anchor="middle" dominant-baseline="middle" '
            f'font-size="28" font-weight="bold" fill="#1A237E">{total}</text>'
            f'<text x="100" y="126" text-anchor="middle" font-size="11" fill="#607d8b">findings</text>'
            f'</svg>')


def _render_remediation_html(rec_raw: str) -> str:
    if not rec_raw or rec_raw.strip() in ("", "&#8212;", "—"):
        return "<p class='muted'>No remediation available.</p>"
    rec_raw = rec_raw.strip()
    if rec_raw.startswith("{"):
        try:
            obj = json.loads(rec_raw)
            parts: List[str] = []
            if obj.get("context"):
                parts.append(f"<p>{_h(obj['context'])}</p>")
            ia = obj.get("immediate_assessment") or []
            if ia:
                parts.append("<h4>Immediate Assessment</h4><ul>")
                for item in ia:
                    parts.append(f"<li>{_h(item)}</li>")
                parts.append("</ul>")
            pc = obj.get("patch_commands")
            if pc:
                parts.append(f'<h4>Patch Commands</h4><pre class="code">{_h(pc)}</pre>')
            steps = obj.get("steps") or []
            if steps:
                parts.append("<h4>Steps</h4><ol>")
                for step in steps:
                    parts.append(f"<li>{_h(step)}</li>")
                parts.append("</ol>")
            cc = obj.get("compensating_controls") or []
            if cc:
                parts.append("<h4>Compensating Controls</h4><ul>")
                for ctrl in cc:
                    parts.append(f"<li>{_h(ctrl)}</li>")
                parts.append("</ul>")
            val = obj.get("validation") or []
            if val:
                parts.append("<h4>Validation Steps</h4><ol>")
                for v in val:
                    parts.append(f"<li>{_h(v)}</li>")
                parts.append("</ol>")
            pn = obj.get("patch_notes")
            if pn:
                parts.append(f'<p class="note"><strong>Note:</strong> {_h(pn)}</p>')
            if parts:
                return "".join(parts)
        except Exception:
            pass
    lines = rec_raw.split("\n")
    return "<p>" + "<br>".join(_h(line) for line in lines) + "</p>"


def _cve_chips(cve_ids_raw: str, cve_id: str) -> str:
    ids: List[str] = []
    if cve_ids_raw:
        try:
            parsed = json.loads(cve_ids_raw)
            if isinstance(parsed, list):
                ids = [str(x) for x in parsed if x]
        except Exception:
            pass
    if not ids and cve_id:
        ids = [cve_id]
    if not ids:
        return "<span class='muted'>—</span>"
    chips = "".join(
        f'<span class="cve-chip">{_html_lib.escape(c)}</span>' for c in ids
    )
    return chips


CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;color:#263238;background:#f4f6f9;display:flex;flex-direction:column;height:100vh;overflow:hidden}
a{color:inherit;text-decoration:none}

/* ── header ── */
#topbar{background:#1A237E;color:#fff;padding:0 20px;height:52px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.35)}
#topbar .report-title{font-size:15px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:55%}
#topbar .meta{display:flex;align-items:center;gap:8px;font-size:12px;opacity:.9}
.classif-chip{background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);border-radius:4px;padding:2px 8px;font-size:11px;font-weight:600;letter-spacing:.04em}

/* ── layout ── */
#shell{display:flex;flex:1;overflow:hidden}

/* ── sidebar ── */
#sidebar{width:260px;background:#1e2d4e;color:#c8d6ef;flex-shrink:0;display:flex;flex-direction:column;overflow:hidden}
#sidebar-inner{overflow-y:auto;flex:1;padding-bottom:16px}
#sidebar-inner::-webkit-scrollbar{width:4px}
#sidebar-inner::-webkit-scrollbar-thumb{background:#3a5080;border-radius:2px}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#7a9cc0;padding:14px 16px 4px}
.nav-item{display:flex;align-items:center;gap:8px;padding:7px 16px;cursor:pointer;border-radius:0;transition:background .15s;font-size:13px;color:#c8d6ef;border-left:3px solid transparent}
.nav-item:hover{background:rgba(255,255,255,.07)}
.nav-item.active{background:rgba(255,255,255,.13);color:#fff;border-left-color:#5c9cf5;font-weight:600}
.nav-item .nav-dot{font-size:9px;flex-shrink:0}
.nav-item .nav-text{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.nav-item .sev-badge{font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;flex-shrink:0}
.nav-divider{height:1px;background:rgba(255,255,255,.08);margin:6px 12px}

/* finding filters */
.finding-filters{padding:6px 12px 4px}
.sev-filter-row{display:flex;flex-wrap:wrap;gap:3px;margin-bottom:6px}
.sev-btn{font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;cursor:pointer;border:1px solid transparent;opacity:.7;transition:opacity .15s}
.sev-btn.active{opacity:1;border-color:rgba(255,255,255,.4)}
.search-box{width:100%;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.15);border-radius:4px;color:#fff;padding:5px 8px;font-size:12px;outline:none}
.search-box::placeholder{color:rgba(255,255,255,.4)}
.search-box:focus{border-color:rgba(92,156,245,.6)}

/* ── content ── */
#content{flex:1;overflow-y:auto;padding:28px 32px}
#content::-webkit-scrollbar{width:6px}
#content::-webkit-scrollbar-thumb{background:#cfd8dc;border-radius:3px}

.page{display:none}
.page.active{display:block}

/* ── cards / sections ── */
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:20px;overflow:hidden}
.card-header{padding:14px 20px;border-bottom:1px solid #eceff1;font-size:15px;font-weight:700;color:#1A237E;display:flex;align-items:center;gap:8px}
.card-body{padding:20px}
.section-title{font-size:17px;font-weight:700;color:#1A237E;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid #E8EAF6}

/* ── doc-control table ── */
.dc-table{width:100%;border-collapse:collapse}
.dc-table td{padding:8px 12px;border-bottom:1px solid #eceff1;font-size:13px}
.dc-table td:first-child{width:160px;font-weight:600;color:#546e7a;background:#f9fafb}

/* ── stat cards ── */
.stat-row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.stat-card{flex:1;min-width:110px;background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:16px 18px;text-align:center}
.stat-card .stat-num{font-size:32px;font-weight:800;line-height:1}
.stat-card .stat-label{font-size:11px;color:#78909c;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}

/* ── donut legend ── */
.donut-wrap{display:flex;align-items:center;gap:28px;flex-wrap:wrap}
.donut-legend{display:flex;flex-direction:column;gap:6px}
.legend-row{display:flex;align-items:center;gap:8px;font-size:13px}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
.legend-count{font-weight:700;min-width:24px}

/* ── generic table ── */
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table th{background:#E8EAF6;color:#1A237E;font-weight:700;padding:8px 12px;text-align:left;font-size:12px}
.data-table td{padding:7px 12px;border-bottom:1px solid #eceff1;vertical-align:top}
.data-table tr:last-child td{border-bottom:none}
.data-table tr:nth-child(even) td{background:#f9fafb}

/* ── asset chip / cve chip ── */
.cve-chip{display:inline-block;background:#E3F2FD;color:#1565C0;border:1px solid #BBDEFB;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:600;margin:1px}
.tool-chip{display:inline-block;background:#EDE7F6;color:#4527A0;border-radius:4px;padding:2px 8px;font-size:12px;margin:2px}

/* ── SLA table ── */
.sla-table{width:100%;border-collapse:collapse;font-size:13px}
.sla-table th{padding:7px 12px;text-align:left;font-size:12px;font-weight:700;color:#1A237E;background:#E8EAF6}
.sla-table td{padding:8px 12px;border-bottom:1px solid #eceff1}
.sev-pill{display:inline-block;border-radius:4px;padding:2px 10px;font-size:11px;font-weight:700;letter-spacing:.03em}

/* ── finding header band ── */
.finding-header{padding:18px 24px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.finding-id-badge{width:40px;height:40px;border-radius:50%;background:rgba(255,255,255,.25);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;flex-shrink:0;border:2px solid rgba(255,255,255,.5)}
.finding-title-area{flex:1;min-width:0}
.finding-title-area h2{font-size:16px;font-weight:700;line-height:1.3;word-break:break-word}
.finding-title-area .fid-label{font-size:11px;opacity:.8;margin-bottom:2px}
.finding-sev-chip{padding:4px 12px;border-radius:4px;font-size:12px;font-weight:800;letter-spacing:.06em;border:2px solid rgba(255,255,255,.4);white-space:nowrap}

/* ── meta strip ── */
.meta-strip{background:#f1f3f4;padding:10px 24px;display:flex;flex-wrap:wrap;gap:18px;font-size:12px;border-bottom:1px solid #e0e0e0}
.meta-item{display:flex;flex-direction:column;gap:1px}
.meta-item .mi-label{font-weight:700;color:#546e7a;font-size:10px;text-transform:uppercase;letter-spacing:.05em}
.meta-item .mi-val{color:#263238}

/* ── finding sub-tabs ── */
.ftab-bar{display:flex;gap:0;border-bottom:2px solid #e0e0e0;padding:0 24px;background:#fff}
.ftab-btn{padding:10px 18px;cursor:pointer;font-size:13px;font-weight:600;color:#78909c;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color .15s,border-color .15s}
.ftab-btn:hover{color:#1A237E}
.ftab-btn.active{color:#1A237E;border-bottom-color:#1A237E}
.ftab-panel{padding:22px 24px;display:none}
.ftab-panel.active{display:block}

/* ── text content ── */
.prose{line-height:1.7;white-space:pre-wrap;word-break:break-word;font-size:13px;color:#37474f}
pre.code{background:#f5f7f9;border:1px solid #dde2ea;border-radius:6px;padding:14px 16px;font-size:12px;overflow-x:auto;white-space:pre;color:#263238;line-height:1.55}
.evidence-pre{background:#1e2d4e;color:#c8d6ef;border-radius:6px;padding:16px;font-size:12px;overflow:auto;max-height:420px;line-height:1.55;white-space:pre-wrap;word-break:break-word}
h4{font-size:13px;font-weight:700;color:#1A237E;margin:14px 0 6px}
ul,ol{padding-left:20px;margin:6px 0}
li{margin:3px 0;line-height:1.6;font-size:13px}
p{margin:6px 0;line-height:1.65;font-size:13px}
.note{background:#FFF8E1;border-left:3px solid #F9A825;padding:8px 12px;border-radius:4px;font-size:12px}
.muted{color:#9e9e9e;font-style:italic}

/* ── hosts table ── */
.hosts-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
.hosts-table th{background:#E8EAF6;color:#1A237E;padding:6px 10px;text-align:left;font-size:11px;font-weight:700}
.hosts-table td{padding:6px 10px;border-bottom:1px solid #eceff1}
.hosts-table td:first-child{color:#546e7a;font-weight:600;width:36px}

/* ── tracking table ── */
.track-table{width:100%;border-collapse:collapse;font-size:13px}
.track-table td{padding:8px 12px;border-bottom:1px solid #eceff1;vertical-align:top}
.track-table td:first-child{width:160px;font-weight:600;color:#546e7a;background:#f9fafb}

/* ── prev/next nav ── */
.finding-nav-btns{display:flex;justify-content:space-between;padding:16px 24px;border-top:1px solid #eceff1;margin-top:4px}
.nav-arrow-btn{padding:8px 18px;border:1px solid #1A237E;color:#1A237E;background:#fff;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer;transition:background .15s}
.nav-arrow-btn:hover{background:#E8EAF6}
.nav-arrow-btn:disabled{opacity:.3;cursor:not-allowed}

/* ── remediation accordion ── */
.rem-acc-item{border:1px solid #e0e0e0;border-radius:6px;margin-bottom:8px;overflow:hidden}
.rem-acc-hdr{padding:11px 16px;cursor:pointer;display:flex;align-items:center;gap:10px;background:#fafafa;font-size:13px;font-weight:600;color:#263238;user-select:none}
.rem-acc-hdr:hover{background:#f0f4f8}
.rem-acc-hdr .acc-toggle{font-size:16px;color:#78909c;margin-left:auto}
.rem-acc-body{display:none;padding:16px;border-top:1px solid #e0e0e0;background:#fff}
.rem-acc-body.open{display:block}

/* ── retest chip ── */
.retest-chip{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.retest-pending{background:#FFF3E0;color:#E65100}
.retest-passed{background:#E8F5E9;color:#2E7D32}
.retest-failed{background:#FFEBEE;color:#C62828}
.retest-na{background:#ECEFF1;color:#546e7a}

/* ── exec summary ── */
.exec-summary{line-height:1.8;font-size:14px;color:#37474f;white-space:pre-wrap;word-break:break-word}

/* ── editable mode ── */
.edit-btn{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.35);color:#fff;border-radius:5px;padding:4px 12px;font-size:12px;font-weight:600;cursor:pointer;transition:background .15s}
.edit-btn:hover{background:rgba(255,255,255,.25)}
.edit-btn.active{background:#FFA726;border-color:#FFB74D;color:#1a1a1a}
.save-btn{background:#43A047;border:1px solid #388E3C;color:#fff;border-radius:5px;padding:4px 12px;font-size:12px;font-weight:600;cursor:pointer;display:none;margin-left:6px}
.save-btn:hover{background:#388E3C}
.editable-field[contenteditable="true"]{outline:2px solid #2979ff;background:rgba(41,121,255,.04);border-radius:4px;padding:8px;min-height:40px;cursor:text;position:relative}
.editable-field[contenteditable="true"]:empty:before{content:attr(data-placeholder);color:#9e9e9e;font-style:italic;pointer-events:none}
.edit-mode-banner{display:none;background:#E3F2FD;border:1px solid #90CAF9;border-radius:6px;padding:8px 14px;font-size:12px;color:#1565C0;margin-bottom:16px;align-items:center;gap:8px}
.edit-mode-banner.visible{display:flex}

/* ── asset view ── */
.asset-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-bottom:24px}
.asset-card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);overflow:hidden;display:flex;flex-direction:column}
.asset-card-header{padding:12px 16px;background:#1A237E;color:#fff;display:flex;align-items:center;justify-content:space-between;gap:8px}
.asset-card-hostname{font-size:13px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.asset-card-ip{font-size:11px;opacity:.75;flex-shrink:0}
.asset-risk-bar{display:flex;gap:4px;padding:8px 14px;border-bottom:1px solid #eceff1;flex-wrap:wrap}
.asset-finding-list{padding:4px 0;flex:1}
.asset-finding-row{display:flex;align-items:center;gap:8px;padding:7px 14px;border-bottom:1px solid #f5f5f5;cursor:pointer;transition:background .12s;font-size:12px}
.asset-finding-row:last-child{border-bottom:none}
.asset-finding-row:hover{background:#f0f4f8}
.asset-finding-title{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#263238}
.asset-summary-bar{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:20px}
.asset-summary-chip{background:#E8EAF6;color:#1A237E;border-radius:20px;padding:4px 14px;font-size:13px;font-weight:700}

/* ── print ── */
@media print{
  #sidebar{display:none}
  #topbar{position:static}
  #content{overflow:visible;height:auto}
  #shell{overflow:visible;height:auto}
  body{height:auto;overflow:auto}
  .page{display:block !important;page-break-after:always}
  .finding-nav-btns{display:none}
}
"""

JS = r"""
var _activeSev = 'all';

function showPage(id) {
  document.querySelectorAll('.page').forEach(function(p){ p.classList.remove('active'); });
  var pg = document.getElementById(id);
  if(pg) pg.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(function(n){ n.classList.remove('active'); });
  var ni = document.querySelector('[data-page="'+id+'"]');
  if(ni) ni.classList.add('active');
  var c = document.getElementById('content');
  if(c) c.scrollTop = 0;
}

function filterSev(sev) {
  _activeSev = sev;
  document.querySelectorAll('.sev-btn').forEach(function(b){
    b.classList.toggle('active', b.dataset.sev === sev);
  });
  applyFindingFilter();
}

function applyFindingFilter() {
  var q = (document.getElementById('finding-search')||{}).value || '';
  q = q.toLowerCase().trim();
  document.querySelectorAll('.finding-nav-item').forEach(function(el){
    var sev = el.dataset.sev || '';
    var txt = (el.dataset.title || '').toLowerCase();
    var sevOk = (_activeSev === 'all' || sev === _activeSev);
    var txtOk = (!q || txt.indexOf(q) !== -1);
    el.style.display = (sevOk && txtOk) ? '' : 'none';
  });
}

function doSearch() { applyFindingFilter(); }

function showFindingTab(idx, tab) {
  var prefix = 'ftab-'+idx+'-';
  document.querySelectorAll('[id^="'+prefix+'"]').forEach(function(p){
    p.classList.remove('active');
  });
  var target = document.getElementById(prefix+tab);
  if(target) target.classList.add('active');
  document.querySelectorAll('[data-fidx="'+idx+'"]').forEach(function(b){
    b.classList.toggle('active', b.dataset.tab === tab);
  });
}

function toggleAcc(id) {
  var body = document.getElementById(id);
  var icon = document.getElementById(id+'-icon');
  if(!body) return;
  var open = body.classList.toggle('open');
  if(icon) icon.textContent = open ? '▲' : '▼';
}

function navFinding(idx) {
  showPage('page-finding-'+idx);
}

/* ── editable mode ── */
var _editMode = false;
var _EDITABLE_IDS = ['editable-exec-summary','editable-conclusion','editable-appendices'];

function toggleEditMode() {
  _editMode = !_editMode;
  _EDITABLE_IDS.forEach(function(id) {
    var el = document.getElementById(id);
    if (!el) return;
    if (_editMode) {
      el.setAttribute('contenteditable', 'true');
    } else {
      el.removeAttribute('contenteditable');
    }
  });
  var btn = document.getElementById('edit-toggle-btn');
  var saveBtn = document.getElementById('save-edit-btn');
  var banner = document.getElementById('edit-mode-banner');
  if (btn) {
    btn.textContent = _editMode ? '✓ Done Editing' : '✏️ Edit';
    btn.classList.toggle('active', _editMode);
  }
  if (saveBtn) saveBtn.style.display = _editMode ? 'inline-block' : 'none';
  if (banner) banner.classList.toggle('visible', _editMode);
}

function saveEditedHtml() {
  /* Snapshot DOM while editable, then strip edit-mode markers before download */
  var clone = document.documentElement.cloneNode(true);
  /* remove contenteditable */
  clone.querySelectorAll('[contenteditable]').forEach(function(el) {
    el.removeAttribute('contenteditable');
    el.style.outline = '';
    el.style.background = '';
    el.style.padding = '';
  });
  /* hide edit UI in clone */
  var editBtn = clone.querySelector('#edit-toggle-btn');
  var saveBtn = clone.querySelector('#save-edit-btn');
  var banner  = clone.querySelector('#edit-mode-banner');
  if (editBtn) editBtn.style.display = 'none';
  if (saveBtn) saveBtn.style.display = 'none';
  if (banner)  banner.style.display  = 'none';
  var html = '<!DOCTYPE html>\n' + clone.outerHTML;
  var blob = new Blob([html], {type: 'text/html;charset=utf-8'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (document.title || 'vapt-report').replace(/[^a-z0-9]/gi,'-').toLowerCase() + '-edited.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}
"""


def generate_html(report: Dict, findings: List[Dict], client_name: str) -> bytes:
    import json as _json

    # ── parse config ─────────────────────────────────────────────────────────
    scope: Dict = {}
    methodology: Dict = {}
    sla_defaults = {
        "critical": "24 hours", "high": "72 hours",
        "medium": "30 days", "low": "90 days", "info": "Best effort",
    }
    sla_map = dict(sla_defaults)
    try:
        scope = _json.loads(report.get("scope_json") or "{}")
    except Exception:
        pass
    try:
        methodology = _json.loads(report.get("methodology_json") or "{}")
    except Exception:
        pass
    try:
        cfg = _json.loads(report.get("sla_config") or "{}")
        if isinstance(cfg, dict):
            sla_map.update({k.lower(): v for k, v in cfg.items() if v})
    except Exception:
        pass

    sorted_findings = sorted(findings, key=_sort_key)
    total = len(findings)
    sev_counts: Dict[str, int] = {}
    for f in findings:
        s = _sev_norm(f.get("severity", "info"))
        sev_counts[s] = sev_counts.get(s, 0) + 1

    report_title = (report.get("title") or "VAPT Report")
    classification = (report.get("classification") or "Confidential")
    version_str = (report.get("version") or "1.0")
    prepared_by = (report.get("prepared_by") or "")
    report_date_raw = report.get("report_date") or ""
    if report_date_raw:
        try:
            report_date_raw = report_date_raw[:10]
        except Exception:
            pass
    exec_summary = (report.get("executive_summary") or "")
    conclusion = (report.get("conclusion") or "")
    appendices_text = (report.get("appendices") or "")
    in_scope = scope.get("in_scope") or []
    out_scope = scope.get("out_of_scope") or []
    phases = methodology.get("phases") or []
    tools = methodology.get("tools") or []
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    p: List[str] = []

    # ── DOCTYPE + head ────────────────────────────────────────────────────────
    p.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_h(report_title)}</title>
<style>{CSS}</style>
</head>
<body>
""")

    # ── top bar ───────────────────────────────────────────────────────────────
    p.append(f"""<div id="topbar">
  <div class="report-title">{_h(report_title)}</div>
  <div class="meta">
    <span class="classif-chip">{_h(classification)}</span>
    <span>v{_h(version_str)}</span>
    <span style="opacity:.5">|</span>
    <span>{_h(client_name)}</span>
    <span style="opacity:.5">|</span>
    <button id="edit-toggle-btn" class="edit-btn" onclick="toggleEditMode()">&#9998; Edit</button>
    <button id="save-edit-btn" class="save-btn" onclick="saveEditedHtml()">&#8681; Save Edits</button>
  </div>
</div>
<div id="shell">
""")

    # ── sidebar ───────────────────────────────────────────────────────────────
    p.append("""<nav id="sidebar"><div id="sidebar-inner">
""")
    p.append("""<div class="nav-section-label">Navigation</div>
<div class="nav-item active" data-page="page-overview" onclick="showPage('page-overview')">
  <span>📋</span><span class="nav-text">Overview</span>
</div>
<div class="nav-item" data-page="page-scope" onclick="showPage('page-scope')">
  <span>🎯</span><span class="nav-text">Scope &amp; Methodology</span>
</div>
<div class="nav-item" data-page="page-assets" onclick="showPage('page-assets')">
  <span>🖥</span><span class="nav-text">Findings by Asset</span>
</div>
<div class="nav-divider"></div>
""")

    # findings section header + filters
    p.append(f"""<div class="nav-section-label">Findings ({total})</div>
<div class="finding-filters">
  <div class="sev-filter-row">
    <span class="sev-btn active" data-sev="all"
      style="background:rgba(255,255,255,.15);color:#fff"
      onclick="filterSev('all')">ALL</span>
""")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev_counts.get(sev, 0):
            bg = _SEV_BG[sev]
            fg = _SEV_FG[sev]
            p.append(f"""    <span class="sev-btn" data-sev="{sev}"
      style="background:{bg};color:{fg}"
      onclick="filterSev('{sev}')">{_SEV_LABEL[sev][:3]} {sev_counts[sev]}</span>
""")
    p.append("""  </div>
  <input class="search-box" id="finding-search" type="text" placeholder="Search findings…" oninput="doSearch()">
</div>
""")

    # per-finding nav items
    for fi, f in enumerate(sorted_findings):
        sev = _sev_norm(f.get("severity", "info"))
        bg = _SEV_BG.get(sev, "#9e9e9e")
        fg = _SEV_FG.get(sev, "#fff")
        title_short = (f.get("title") or "Untitled")
        p.append(f"""<div class="nav-item finding-nav-item" data-page="page-finding-{fi}"
  data-sev="{sev}" data-title="{_html_lib.escape(title_short.lower())}"
  onclick="showPage('page-finding-{fi}')">
  <span class="nav-dot" style="color:{bg}">●</span>
  <span class="nav-text">{_h("F-" + str(fi+1).zfill(2) + " " + title_short)}</span>
  <span class="sev-badge" style="background:{bg};color:{fg}">{_SEV_LABEL.get(sev,'?')[:3]}</span>
</div>
""")

    p.append("""<div class="nav-divider"></div>
<div class="nav-item" data-page="page-remediation" onclick="showPage('page-remediation')">
  <span>🛠</span><span class="nav-text">Remediation Plan</span>
</div>
<div class="nav-item" data-page="page-appendices" onclick="showPage('page-appendices')">
  <span>📎</span><span class="nav-text">Appendices</span>
</div>
</div></nav>
""")

    # ── content panel ─────────────────────────────────────────────────────────
    p.append('<div id="content">\n')
    p.append('<div id="edit-mode-banner" class="edit-mode-banner">&#9998; Edit mode active &mdash; click any highlighted section to edit. Use &ldquo;Save Edits&rdquo; to download the updated file.</div>\n')

    # ════════════════════════════════════════════════════════════════════════
    # PAGE: OVERVIEW
    # ════════════════════════════════════════════════════════════════════════
    p.append('<div class="page active" id="page-overview">\n')
    p.append('<div class="section-title">📋 Overview</div>\n')

    # document control
    p.append("""<div class="card">
  <div class="card-header">Document Control</div>
  <div class="card-body" style="padding:0">
    <table class="dc-table">
""")
    for label, val in [
        ("Report Title", _h(report_title)),
        ("Client", _h(client_name)),
        ("Classification", _h(classification)),
        ("Version", _h(version_str)),
        ("Prepared By", _h(prepared_by) if prepared_by else "&#8212;"),
        ("Report Date", _h(report_date_raw) if report_date_raw else "&#8212;"),
    ]:
        p.append(f"      <tr><td>{label}</td><td>{val}</td></tr>\n")
    p.append("    </table>\n  </div>\n</div>\n")

    # stat cards
    p.append('<div class="stat-row">\n')
    stat_items = [
        (str(total), "Total Findings", "#1A237E"),
        (str(sev_counts.get("critical", 0)), "Critical", "#C62828"),
        (str(sev_counts.get("high", 0)), "High", "#E64A19"),
        (str(sev_counts.get("medium", 0)), "Medium", "#F57F17"),
        (str(len(in_scope)), "In-Scope Assets", "#2E7D32"),
    ]
    for num, label, color in stat_items:
        p.append(f"""  <div class="stat-card">
    <div class="stat-num" style="color:{color}">{num}</div>
    <div class="stat-label">{label}</div>
  </div>
""")
    p.append("</div>\n")

    # donut chart
    donut_svg = _build_donut(sev_counts, total)
    p.append('<div class="card"><div class="card-header">Severity Distribution</div><div class="card-body">\n')
    p.append('<div class="donut-wrap">\n')
    p.append(donut_svg + "\n")
    p.append('<div class="donut-legend">\n')
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            pct = round(100 * cnt / total) if total else 0
            p.append(f"""  <div class="legend-row">
    <div class="legend-dot" style="background:{_SEV_BG[sev]}"></div>
    <span class="legend-count">{cnt}</span>
    <span style="color:#546e7a">{_SEV_LABEL[sev]} ({pct}%)</span>
  </div>
""")
    p.append("</div>\n</div>\n</div></div>\n")

    # executive summary
    p.append('<div class="card"><div class="card-header">Executive Summary</div>'
             '<div class="card-body">'
             '<div class="exec-summary editable-field" id="editable-exec-summary" data-placeholder="Click to edit executive summary...">')
    p.append(_h(exec_summary) if exec_summary else '<span style="color:#9e9e9e;font-style:italic">No executive summary generated.</span>')
    p.append("</div></div></div>\n")

    p.append("</div>\n")  # end page-overview

    # ════════════════════════════════════════════════════════════════════════
    # PAGE: SCOPE & METHODOLOGY
    # ════════════════════════════════════════════════════════════════════════
    p.append('<div class="page" id="page-scope">\n')
    p.append('<div class="section-title">🎯 Scope &amp; Methodology</div>\n')

    # engagement metadata
    eng_rows = []
    for label, key in [("Engagement Type", "engagement_type"), ("Period Start", "period_start"), ("Period End", "period_end")]:
        v = scope.get(key, "")
        if v:
            eng_rows.append((label, v))
    if eng_rows:
        p.append('<div class="card"><div class="card-header">Engagement Details</div><div class="card-body" style="padding:0"><table class="dc-table">\n')
        for label, val in eng_rows:
            p.append(f"<tr><td>{label}</td><td>{_h(val)}</td></tr>\n")
        p.append("</table></div></div>\n")

    # in-scope assets
    if in_scope:
        p.append('<div class="card"><div class="card-header">In-Scope Assets</div><div class="card-body" style="padding:0">'
                 '<table class="data-table"><thead><tr><th>#</th><th>Asset / Host</th></tr></thead><tbody>\n')
        for i, asset in enumerate(in_scope):
            p.append(f'<tr><td style="color:#546e7a;font-weight:600">{i+1}</td><td>{_h(asset)}</td></tr>\n')
        p.append("</tbody></table></div></div>\n")

    # out of scope
    if out_scope:
        p.append('<div class="card"><div class="card-header">Out-of-Scope</div><div class="card-body"><ul>\n')
        for item in out_scope:
            p.append(f"<li>{_h(item)}</li>\n")
        p.append("</ul></div></div>\n")

    # testing phases
    if phases:
        p.append('<div class="card"><div class="card-header">Testing Phases</div><div class="card-body" style="padding:0">'
                 '<table class="data-table"><thead><tr><th>#</th><th>Phase</th><th>Description</th></tr></thead><tbody>\n')
        for i, ph in enumerate(phases):
            p.append(f'<tr><td style="color:#546e7a;font-weight:600;width:36px">{i+1}</td>'
                     f'<td style="font-weight:600;white-space:nowrap">{_h(ph.get("name",""))}</td>'
                     f'<td>{_h(ph.get("description",""))}</td></tr>\n')
        p.append("</tbody></table></div></div>\n")

    # tools
    if tools:
        p.append('<div class="card"><div class="card-header">Tools Used</div><div class="card-body">\n')
        for t in tools:
            p.append(f'<span class="tool-chip">{_h(t)}</span>\n')
        p.append("</div></div>\n")

    # SLA targets
    p.append('<div class="card"><div class="card-header">Remediation SLA Targets</div><div class="card-body" style="padding:0">'
             '<table class="sla-table"><thead><tr><th>Severity</th><th>Target SLA</th></tr></thead><tbody>\n')
    for sev in ["critical", "high", "medium", "low", "info"]:
        bg = _SEV_BG[sev]
        fg = _SEV_FG[sev]
        target = sla_map.get(sev, sla_defaults.get(sev, "—"))
        p.append(f'<tr><td><span class="sev-pill" style="background:{bg};color:{fg}">{_SEV_LABEL[sev]}</span></td>'
                 f'<td>{_h(target)}</td></tr>\n')
    p.append("</tbody></table></div></div>\n")

    p.append("</div>\n")  # end page-scope

    # ════════════════════════════════════════════════════════════════════════
    # PAGE: FINDINGS BY ASSET
    # ════════════════════════════════════════════════════════════════════════
    # Build asset → findings map.
    # Each finding can affect multiple hosts (comma-separated in affected_asset,
    # or richer {ip,dns} objects in evidence JSON → raw.affected_hosts).
    import json as _json

    # asset_map: hostname → {"ip": str, "findings": [(fi, finding_dict)]}
    asset_map: Dict[str, Dict] = {}

    for fi, f in enumerate(sorted_findings):
        # Try evidence JSON first (Nessus CSV path: raw.affected_hosts)
        hosts_from_evidence: List[Dict] = []
        ev_raw = f.get("evidence") or ""
        if ev_raw:
            try:
                ev = _json.loads(ev_raw) if isinstance(ev_raw, str) else ev_raw
                hosts_from_evidence = (ev.get("raw") or {}).get("affected_hosts") or []
            except Exception:
                pass

        if hosts_from_evidence:
            for h in hosts_from_evidence:
                dns = (h.get("dns") or "").strip()
                ip  = (h.get("ip")  or "").strip()
                key = dns or ip
                if not key:
                    continue
                if key not in asset_map:
                    asset_map[key] = {"ip": ip if dns else "", "findings": []}
                asset_map[key]["findings"].append((fi, f))
        else:
            # Fallback: affected_asset comma-separated string
            asset_raw_str = (f.get("affected_asset") or "").strip()
            if asset_raw_str:
                for part in asset_raw_str.split(","):
                    key = part.strip()
                    if not key:
                        continue
                    if key not in asset_map:
                        asset_map[key] = {"ip": "", "findings": []}
                    asset_map[key]["findings"].append((fi, f))
            else:
                # Single-host finding with no comma
                key = asset_raw_str or "Unknown"
                if key not in asset_map:
                    asset_map[key] = {"ip": "", "findings": []}
                asset_map[key]["findings"].append((fi, f))

    # Sort assets: most critical findings first
    def _asset_sort_key(item):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for _, f2 in item[1]["findings"]:
            counts[_sev_norm(f2.get("severity", "info"))] += 1
        return (-counts["critical"], -counts["high"], -counts["medium"], -counts["low"])

    sorted_assets = sorted(asset_map.items(), key=_asset_sort_key)

    p.append('<div class="page" id="page-assets">\n')
    p.append('<div class="section-title">🖥 Findings by Asset</div>\n')

    # summary bar
    p.append('<div class="asset-summary-bar">\n')
    p.append(f'<span class="asset-summary-chip">{len(asset_map)} Asset{"s" if len(asset_map)!=1 else ""}</span>\n')
    p.append(f'<span class="asset-summary-chip">{total} Finding{"s" if total!=1 else ""}</span>\n')
    for sev in ["critical", "high", "medium", "low"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            p.append(f'<span style="background:{_SEV_BG[sev]};color:{_SEV_FG[sev]};border-radius:20px;padding:4px 14px;font-size:13px;font-weight:700">'
                     f'{_SEV_LABEL[sev]} {cnt}</span>\n')
    p.append('</div>\n')

    # asset cards grid
    p.append('<div class="asset-grid">\n')
    for hostname, info in sorted_assets:
        ip_str = info["ip"]
        a_findings = info["findings"]

        # count severities for this asset
        ac = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for _, f2 in a_findings:
            ac[_sev_norm(f2.get("severity", "info"))] += 1

        # header colour = worst severity
        worst = next((s for s in ["critical","high","medium","low","info"] if ac[s] > 0), "info")
        hdr_bg = _SEV_BG[worst]
        hdr_fg = _SEV_FG[worst]

        p.append('<div class="asset-card">\n')
        # card header
        p.append(f'<div class="asset-card-header" style="background:{hdr_bg}">\n')
        p.append(f'  <span class="asset-card-hostname" title="{_h(hostname)}">{_h(hostname)}</span>\n')
        if ip_str and ip_str != hostname:
            p.append(f'  <span class="asset-card-ip">{_h(ip_str)}</span>\n')
        p.append('</div>\n')

        # risk pill bar
        p.append('<div class="asset-risk-bar">\n')
        for sev in ["critical", "high", "medium", "low", "info"]:
            if ac[sev]:
                p.append(f'<span style="background:{_SEV_BG[sev]};color:{_SEV_FG[sev]};border-radius:4px;'
                         f'padding:2px 8px;font-size:11px;font-weight:700">'
                         f'{_SEV_LABEL[sev][:3]} {ac[sev]}</span>\n')
        p.append('</div>\n')

        # finding rows
        p.append('<div class="asset-finding-list">\n')
        for fi2, f2 in sorted(a_findings, key=lambda x: (
            ["critical","high","medium","low","info"].index(_sev_norm(x[1].get("severity","info"))), x[0]
        )):
            sev2 = _sev_norm(f2.get("severity", "info"))
            bg2  = _SEV_BG[sev2]
            fg2  = _SEV_FG[sev2]
            t2   = f2.get("title") or "Untitled"
            p.append(
                f'<div class="asset-finding-row" onclick="showPage(\'page-finding-{fi2}\')" title="{_h(t2)}">\n'
                f'  <span style="background:{bg2};color:{fg2};border-radius:3px;padding:1px 6px;'
                f'font-size:10px;font-weight:700;flex-shrink:0">{_SEV_LABEL.get(sev2,"?")[:3]}</span>\n'
                f'  <span style="color:#546e7a;font-size:11px;font-weight:600;flex-shrink:0">F-{fi2+1:02d}</span>\n'
                f'  <span class="asset-finding-title">{_h(t2)}</span>\n'
                f'</div>\n'
            )
        p.append('</div>\n')  # end finding-list
        p.append('</div>\n')  # end asset-card

    p.append('</div>\n')  # end asset-grid
    p.append('</div>\n')  # end page-assets

    # ════════════════════════════════════════════════════════════════════════
    # PAGES: PER FINDING
    # ════════════════════════════════════════════════════════════════════════
    for fi, f in enumerate(sorted_findings):
        sev = _sev_norm(f.get("severity", "info"))
        sev_bg = _SEV_BG.get(sev, "#9e9e9e")
        sev_fg = _SEV_FG.get(sev, "#fff")
        title = f.get("title") or "Untitled"
        fid = f"F-{fi+1:02d}"
        asset_raw = f.get("affected_asset") or ""
        cvss = f.get("cvss_score")
        cve_id = f.get("cve_id") or ""
        cve_ids_raw = f.get("cve_ids") or ""
        description = f.get("description") or ""
        impact = f.get("impact") or ""
        evidence = f.get("evidence") or ""
        recommendation = f.get("recommendation") or ""
        references = f.get("references") or ""
        retest_status = f.get("retest_status") or "pending"

        # parse multi-host
        if "," in asset_raw:
            hosts = [h.strip() for h in asset_raw.split(",") if h.strip()]
        else:
            hosts = []

        p.append(f'<div class="page" id="page-finding-{fi}">\n')

        # header band
        p.append(f'<div class="card" style="overflow:hidden;margin-bottom:0;border-radius:8px 8px 0 0">\n')
        p.append(f'<div class="finding-header" style="background:{sev_bg};color:{sev_fg}">\n')
        p.append(f'  <div class="finding-id-badge" style="color:{sev_fg}">{_h(fid)}</div>\n')
        p.append(f'  <div class="finding-title-area">\n')
        p.append(f'    <div class="fid-label">Finding {fi+1} of {total}</div>\n')
        p.append(f'    <h2 style="color:{sev_fg}">{_h(title)}</h2>\n')
        p.append(f'  </div>\n')
        p.append(f'  <div class="finding-sev-chip" style="color:{sev_fg}">{_SEV_LABEL.get(sev, "INFO")}</div>\n')
        p.append(f'</div>\n')

        # meta strip
        p.append(f'<div class="meta-strip">\n')
        asset_display = f"Multiple hosts ({len(hosts)})" if hosts else (asset_raw or "—")
        p.append(f'  <div class="meta-item"><span class="mi-label">Asset</span><span class="mi-val">{_h(asset_display)}</span></div>\n')
        cvss_disp = str(cvss) if cvss is not None else "—"
        p.append(f'  <div class="meta-item"><span class="mi-label">CVSS Score</span><span class="mi-val">{_h(cvss_disp)}</span></div>\n')
        p.append(f'  <div class="meta-item"><span class="mi-label">CVE IDs</span><span class="mi-val">{_cve_chips(cve_ids_raw, cve_id)}</span></div>\n')
        p.append(f'  <div class="meta-item"><span class="mi-label">SLA Target</span><span class="mi-val">{_h(sla_map.get(sev, "—"))}</span></div>\n')
        p.append(f'</div>\n')
        p.append('</div>\n')  # close header card

        # affected hosts table (multi-host)
        if hosts:
            p.append('<div class="card" style="border-radius:0;border-top:none;margin-bottom:0">\n')
            p.append('<div class="card-body" style="padding:12px 24px">\n')
            p.append('<div style="font-size:12px;font-weight:700;color:#546e7a;margin-bottom:6px;">AFFECTED HOSTS</div>\n')
            p.append('<table class="hosts-table"><thead><tr><th>#</th><th>Host / IP</th></tr></thead><tbody>\n')
            for hi, host in enumerate(hosts):
                p.append(f'<tr><td>{hi+1}</td><td>{_h(host)}</td></tr>\n')
            p.append('</tbody></table></div></div>\n')

        # sub-tab bar
        p.append(f'<div class="card" style="border-radius:0 0 8px 8px;border-top:none">\n')
        p.append(f'<div class="ftab-bar">\n')
        for tab_name, tab_label in [("desc", "Description"), ("evidence", "Evidence"), ("remediation", "Remediation"), ("tracking", "Tracking")]:
            active_cls = "active" if tab_name == "desc" else ""
            p.append(f'  <div class="ftab-btn {active_cls}" data-fidx="{fi}" data-tab="{tab_name}" '
                     f'onclick="showFindingTab({fi},\'{tab_name}\')">{tab_label}</div>\n')
        p.append('</div>\n')

        # tab: description
        p.append(f'<div class="ftab-panel active" id="ftab-{fi}-desc">\n')
        if description:
            p.append(f'<div class="prose">{_h(description)}</div>\n')
        else:
            p.append('<p class="muted">No description provided.</p>\n')
        if impact:
            p.append(f'<h4 style="margin-top:16px">Impact</h4><div class="prose">{_h(impact)}</div>\n')
        p.append('</div>\n')

        # tab: evidence
        p.append(f'<div class="ftab-panel" id="ftab-{fi}-evidence">\n')
        if evidence:
            p.append(f'<pre class="evidence-pre">{_h(evidence)}</pre>\n')
        else:
            p.append('<p class="muted">No evidence recorded.</p>\n')
        p.append('</div>\n')

        # tab: remediation
        p.append(f'<div class="ftab-panel" id="ftab-{fi}-remediation">\n')
        p.append(_render_remediation_html(recommendation))
        p.append('</div>\n')

        # tab: tracking
        retest_cls = {"pending": "retest-pending", "passed": "retest-passed",
                      "failed": "retest-failed", "not_applicable": "retest-na"}.get(retest_status, "retest-pending")
        p.append(f'<div class="ftab-panel" id="ftab-{fi}-tracking">\n')
        p.append('<table class="track-table">\n')
        track_rows = [
            ("Finding ID", _h(fid)),
            ("Priority", f'<span class="sev-pill" style="background:{sev_bg};color:{sev_fg}">{_SEV_LABEL.get(sev,"INFO")}</span>'),
            ("Target SLA", _h(sla_map.get(sev, "—"))),
            ("CVE IDs", _cve_chips(cve_ids_raw, cve_id)),
            ("CVSS Score", _h(str(cvss) if cvss is not None else "—")),
            ("References", _h(references) if references else "&#8212;"),
            ("Retest Status", f'<span class="retest-chip {retest_cls}">{_h(retest_status.replace("_", " ").title())}</span>'),
        ]
        for label, val in track_rows:
            p.append(f'<tr><td>{label}</td><td>{val}</td></tr>\n')
        p.append('</table>\n</div>\n')

        p.append('</div>\n')  # close card

        # prev/next nav
        p.append('<div class="finding-nav-btns">\n')
        if fi > 0:
            p.append(f'<button class="nav-arrow-btn" onclick="showPage(\'page-finding-{fi-1}\')">← Previous Finding</button>\n')
        else:
            p.append('<button class="nav-arrow-btn" disabled>← Previous Finding</button>\n')
        if fi < total - 1:
            p.append(f'<button class="nav-arrow-btn" onclick="showPage(\'page-finding-{fi+1}\')">Next Finding →</button>\n')
        else:
            p.append('<button class="nav-arrow-btn" disabled>Next Finding →</button>\n')
        p.append('</div>\n')

        p.append('</div>\n')  # end page-finding-{fi}

    # ════════════════════════════════════════════════════════════════════════
    # PAGE: REMEDIATION PLAN
    # ════════════════════════════════════════════════════════════════════════
    p.append('<div class="page" id="page-remediation">\n')
    p.append('<div class="section-title">🛠 Remediation Plan</div>\n')

    # priority action table
    p.append('<div class="card"><div class="card-header">Priority Action Table</div><div class="card-body" style="padding:0">')
    p.append('<table class="data-table"><thead><tr>'
             '<th>ID</th><th>Finding</th><th>Severity</th><th>Asset</th><th>Target SLA</th><th>Status</th>'
             '</tr></thead><tbody>\n')
    for fi, f in enumerate(sorted_findings):
        sev = _sev_norm(f.get("severity", "info"))
        sev_bg = _SEV_BG.get(sev, "#9e9e9e")
        sev_fg = _SEV_FG.get(sev, "#fff")
        light_bg = _SEV_LIGHT.get(sev, "#fff")
        asset_raw = f.get("affected_asset") or ""
        if "," in asset_raw:
            hosts = [h.strip() for h in asset_raw.split(",") if h.strip()]
            asset_display = f"Multiple hosts ({len(hosts)})"
        else:
            asset_display = asset_raw or "—"
        retest_status = f.get("retest_status") or "pending"
        retest_cls = {"pending": "retest-pending", "passed": "retest-passed",
                      "failed": "retest-failed", "not_applicable": "retest-na"}.get(retest_status, "retest-pending")
        p.append(f'<tr style="background:{light_bg}">'
                 f'<td><a href="#" onclick="showPage(\'page-finding-{fi}\');return false" style="color:#1A237E;font-weight:700">F-{fi+1:02d}</a></td>'
                 f'<td style="max-width:280px">{_h(f.get("title",""))}</td>'
                 f'<td><span class="sev-pill" style="background:{sev_bg};color:{sev_fg}">{_SEV_LABEL.get(sev,"?")}</span></td>'
                 f'<td style="font-size:12px">{_h(asset_display)}</td>'
                 f'<td style="font-size:12px">{_h(sla_map.get(sev,"—"))}</td>'
                 f'<td><span class="retest-chip {retest_cls}">{_h(retest_status.replace("_"," ").title())}</span></td>'
                 f'</tr>\n')
    p.append('</tbody></table></div></div>\n')

    # remediation detail accordions
    p.append('<div class="card"><div class="card-header">Detailed Remediation Steps</div><div class="card-body">\n')
    for fi, f in enumerate(sorted_findings):
        sev = _sev_norm(f.get("severity", "info"))
        sev_bg = _SEV_BG.get(sev, "#9e9e9e")
        sev_fg = _SEV_FG.get(sev, "#fff")
        title = f.get("title") or "Untitled"
        acc_id = f"rem-acc-{fi}"
        p.append(f'<div class="rem-acc-item">\n')
        p.append(f'  <div class="rem-acc-hdr" onclick="toggleAcc(\'{acc_id}\')">\n')
        p.append(f'    <span class="sev-pill" style="background:{sev_bg};color:{sev_fg};font-size:10px;padding:1px 7px">F-{fi+1:02d}</span>\n')
        p.append(f'    <span>{_h(title)}</span>\n')
        p.append(f'    <span class="acc-toggle" id="{acc_id}-icon">▼</span>\n')
        p.append(f'  </div>\n')
        p.append(f'  <div class="rem-acc-body" id="{acc_id}">\n')
        p.append(_render_remediation_html(f.get("recommendation") or ""))
        p.append(f'  </div>\n</div>\n')
    p.append('</div></div>\n')

    p.append('</div>\n')  # end page-remediation

    # ════════════════════════════════════════════════════════════════════════
    # PAGE: APPENDICES
    # ════════════════════════════════════════════════════════════════════════
    p.append('<div class="page" id="page-appendices">\n')
    p.append('<div class="section-title">📎 Appendices</div>\n')

    p.append('<div class="card"><div class="card-header">Conclusion</div>'
             '<div class="card-body">'
             '<div class="exec-summary editable-field" id="editable-conclusion" data-placeholder="Click to edit conclusion...">')
    p.append(_h(conclusion) if conclusion else '<span style="color:#9e9e9e;font-style:italic">No conclusion generated.</span>')
    p.append('</div></div></div>\n')

    p.append('<div class="card"><div class="card-header">Appendices</div>'
             '<div class="card-body">'
             '<div class="prose editable-field" id="editable-appendices" data-placeholder="Click to edit appendices...">')
    p.append(_h(appendices_text) if appendices_text else '<span style="color:#9e9e9e;font-style:italic">No appendices generated.</span>')
    p.append('</div></div></div>\n')

    p.append(f'<div class="card"><div class="card-body" style="text-align:center;color:#9e9e9e;font-size:12px">'
             f'Generated by Owlet · {_h(gen_ts)}</div></div>\n')

    p.append('</div>\n')  # end page-appendices

    # ── close layout + JS ─────────────────────────────────────────────────
    p.append(f"""</div></div>
<script>{JS}</script>
</body>
</html>
""")

    return "".join(p).encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# COMPARISON REPORT HTML
# ─────────────────────────────────────────────────────────────────────────────

_CMP_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f2f5;color:#263238;min-height:100vh}
#topbar{position:sticky;top:0;z-index:100;background:#1A237E;color:#fff;display:flex;align-items:center;
  justify-content:space-between;padding:10px 24px;gap:12px}
#topbar .logo{font-weight:800;font-size:15px;letter-spacing:.5px}
#topbar .subtitle{font-size:12px;opacity:.75}
.edit-btn{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.35);color:#fff;border-radius:5px;
  padding:4px 12px;font-size:12px;font-weight:600;cursor:pointer;transition:background .15s}
.edit-btn:hover{background:rgba(255,255,255,.25)}
.edit-btn.active{background:#FFA726;border-color:#FFB74D;color:#1a1a1a}
.save-btn{background:#43A047;border:1px solid #388E3C;color:#fff;border-radius:5px;
  padding:4px 12px;font-size:12px;font-weight:600;cursor:pointer;display:none;margin-left:6px}
.save-btn:hover{background:#388E3C}
.container{max-width:1100px;margin:0 auto;padding:24px 16px}
.vs-header{display:flex;gap:16px;margin-bottom:20px}
.vs-card{flex:1;background:#fff;border-radius:10px;padding:16px 20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.vs-card.baseline{border-left:4px solid #1565C0}
.vs-card.latest{border-left:4px solid #2E7D32}
.vs-label{font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  margin-bottom:4px;color:#78909c}
.vs-title{font-size:15px;font-weight:700;color:#1a237e;margin-bottom:2px}
.vs-meta{font-size:12px;color:#78909c}
.vs-arrow{display:flex;align-items:center;font-size:28px;color:#9e9e9e;padding:0 4px}
.stat-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.stat-card{flex:1;min-width:140px;background:#fff;border-radius:10px;padding:16px 20px;
  text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.stat-num{font-size:32px;font-weight:800}
.stat-label{font-size:12px;color:#78909c;margin-top:4px;font-weight:600}
.stat-delta{font-size:12px;margin-top:6px;font-weight:700}
.tabs{display:flex;gap:0;margin-bottom:0;border-bottom:2px solid #e0e0e0}
.tab{padding:10px 22px;font-size:13px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;
  margin-bottom:-2px;transition:all .15s;color:#78909c}
.tab.active{color:#1A237E;border-bottom-color:#1A237E}
.tab:hover:not(.active){background:#f5f5f5}
.panel{display:none;background:#fff;border-radius:0 0 10px 10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.panel.active{display:block}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;
  color:#78909c;padding:10px 14px;border-bottom:2px solid #e0e0e0;background:#fafafa}
td{padding:11px 14px;border-bottom:1px solid #f0f0f0;font-size:13px;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr.fixed-row{border-left:3px solid #2E7D32}
tr.new-row{border-left:3px solid #C62828}
tr.persist-row{border-left:3px solid #F57F17}
tr:hover td{background:#fafafa}
.sev-chip{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:.5px}
.empty-state{padding:32px;text-align:center;color:#9e9e9e;font-size:14px}
.arrow-up{color:#C62828;font-weight:700}
.arrow-down{color:#2E7D32;font-weight:700}
.edit-mode-banner{display:none;background:#E3F2FD;border:1px solid #90CAF9;border-radius:6px;
  padding:8px 14px;font-size:12px;color:#1565C0;margin-bottom:16px;align-items:center;gap:8px}
.edit-mode-banner.visible{display:flex}
.editable-field[contenteditable="true"]{outline:2px solid #2979ff;background:rgba(41,121,255,.04);
  border-radius:4px;padding:8px;min-height:40px;cursor:text}
.footer{text-align:center;font-size:11px;color:#9e9e9e;margin-top:32px;padding:16px}
@media(max-width:640px){.vs-header{flex-direction:column}.vs-arrow{display:none}.stat-row{gap:8px}}
"""

_CMP_JS = r"""
function showTab(name) {
  document.querySelectorAll('.tab').forEach(function(t){ t.classList.toggle('active', t.dataset.tab===name); });
  document.querySelectorAll('.panel').forEach(function(p){ p.classList.toggle('active', p.id==='panel-'+name); });
}
var _editMode = false;
function toggleEditMode() {
  _editMode = !_editMode;
  var btn = document.getElementById('edit-toggle-btn');
  var saveBtn = document.getElementById('save-edit-btn');
  var banner = document.getElementById('edit-mode-banner');
  document.querySelectorAll('.editable-field').forEach(function(el) {
    if (_editMode) { el.setAttribute('contenteditable','true'); }
    else { el.removeAttribute('contenteditable'); }
  });
  if (btn) { btn.textContent = _editMode ? '✓ Done Editing' : '✏️ Edit'; btn.classList.toggle('active', _editMode); }
  if (saveBtn) saveBtn.style.display = _editMode ? 'inline-block' : 'none';
  if (banner) banner.classList.toggle('visible', _editMode);
}
function saveEditedHtml() {
  var clone = document.documentElement.cloneNode(true);
  clone.querySelectorAll('[contenteditable]').forEach(function(el){ el.removeAttribute('contenteditable'); });
  var editBtn = clone.querySelector('#edit-toggle-btn');
  var saveBtn = clone.querySelector('#save-edit-btn');
  var banner  = clone.querySelector('#edit-mode-banner');
  if (editBtn) editBtn.style.display='none';
  if (saveBtn) saveBtn.style.display='none';
  if (banner)  banner.style.display='none';
  var html = '<!DOCTYPE html>\n' + clone.outerHTML;
  var blob = new Blob([html], {type:'text/html;charset=utf-8'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (document.title||'vapt-compare').replace(/[^a-z0-9]/gi,'-').toLowerCase()+'-edited.html';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}
"""


def generate_comparison_html(payload: dict, client_name: str) -> bytes:
    """Generate a self-contained HTML comparison report."""
    ra = payload.get("report_a", {})
    rb = payload.get("report_b", {})
    stats = payload.get("stats", {})
    fixed = payload.get("fixed", [])
    new_f = payload.get("new_findings", [])
    persist = payload.get("persisting", [])

    title_a = ra.get("title") or "Report A"
    title_b = rb.get("title") or "Report B"
    ver_a = ra.get("version") or ""
    ver_b = rb.get("version") or ""
    date_a = ra.get("report_date") or ra.get("created_at", "")[:10] if ra.get("created_at") else ""
    date_b = rb.get("report_date") or rb.get("created_at", "")[:10] if rb.get("created_at") else ""
    score_a = stats.get("score_a", 0)
    score_b = stats.get("score_b", 0)
    delta = score_b - score_a
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    page_title = f"VAPT Comparison — {_h(client_name)}"

    def sev_chip(sev: str) -> str:
        s = (sev or "info").lower()
        bg = _SEV_BG.get(s, "#9e9e9e")
        fg = _SEV_FG.get(s, "#fff")
        label = _SEV_LABEL.get(s, s.upper())
        return f'<span class="sev-chip" style="background:{bg};color:{fg}">{label}</span>'

    def finding_row(f: dict, row_cls: str) -> str:
        return (f'<tr class="{row_cls}">'
                f'<td>{_h(f.get("title") or "")}</td>'
                f'<td>{sev_chip(f.get("severity",""))}</td>'
                f'<td style="color:#546e7a">{_h(f.get("affected_asset") or "—")}</td>'
                f'</tr>\n')

    def persist_row(pair: dict) -> str:
        fa, fb = pair.get("a", {}), pair.get("b", {})
        sa = (fa.get("severity") or "info").lower()
        sb = (fb.get("severity") or "info").lower()
        sev_order = ["critical", "high", "medium", "low", "info", "informational"]
        ra_idx = sev_order.index(sa) if sa in sev_order else 5
        rb_idx = sev_order.index(sb) if sb in sev_order else 5
        if ra_idx < rb_idx:
            arrow = '<span class="arrow-down">&#8595; Improved</span>'
        elif ra_idx > rb_idx:
            arrow = '<span class="arrow-up">&#8593; Worsened</span>'
        else:
            arrow = '<span style="color:#78909c">&#8212; Same</span>'
        change = f'{sev_chip(sa)} &#8594; {sev_chip(sb)} {arrow}' if sa != sb else sev_chip(sb)
        return (f'<tr class="persist-row">'
                f'<td>{_h(fb.get("title") or "")}</td>'
                f'<td>{change}</td>'
                f'<td style="color:#546e7a">{_h(fb.get("affected_asset") or "—")}</td>'
                f'</tr>\n')

    def table_wrap(rows: str, empty_msg: str) -> str:
        if not rows.strip():
            return f'<div class="empty-state">{empty_msg}</div>'
        return (f'<table><thead><tr>'
                f'<th>Finding</th><th>Severity</th><th>Affected Asset</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>')

    fixed_rows = "".join(finding_row(f, "fixed-row") for f in sorted(fixed, key=lambda x: _SEV_ORDER.index((x.get("severity") or "info").lower()) if (x.get("severity") or "info").lower() in _SEV_ORDER else 9))
    new_rows = "".join(finding_row(f, "new-row") for f in sorted(new_f, key=lambda x: _SEV_ORDER.index((x.get("severity") or "info").lower()) if (x.get("severity") or "info").lower() in _SEV_ORDER else 9))
    persist_rows = "".join(persist_row(p) for p in sorted(persist, key=lambda x: _SEV_ORDER.index((x.get("b", {}).get("severity") or "info").lower()) if (x.get("b", {}).get("severity") or "info").lower() in _SEV_ORDER else 9))

    delta_color = "#2E7D32" if delta >= 0 else "#C62828"
    delta_str = (f'<span style="color:{delta_color}">{"+" if delta >= 0 else ""}{delta}</span>')

    p: List[str] = []
    p.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VAPT Comparison — {_h(client_name)}</title>
<style>{_CMP_CSS}</style>
</head>
<body>
<div id="topbar">
  <div>
    <div class="logo">&#128202; VAPT Comparison &mdash; {_h(client_name)}</div>
    <div class="subtitle">Generated {gen_ts}</div>
  </div>
  <div style="display:flex;align-items:center;gap:8px">
    <button id="edit-toggle-btn" class="edit-btn" onclick="toggleEditMode()">&#9998; Edit</button>
    <button id="save-edit-btn" class="save-btn" onclick="saveEditedHtml()">&#8681; Save Edits</button>
  </div>
</div>
<div class="container">
<div id="edit-mode-banner" class="edit-mode-banner">&#9998; Edit mode active &mdash; click any highlighted section to edit.</div>

<div class="vs-header">
  <div class="vs-card baseline">
    <div class="vs-label">Baseline</div>
    <div class="vs-title">{_h(title_a)}</div>
    <div class="vs-meta">{_h(ver_a)}{" &middot; " + _h(date_a) if date_a else ""}</div>
  </div>
  <div class="vs-arrow">&#8594;</div>
  <div class="vs-card latest">
    <div class="vs-label">Latest</div>
    <div class="vs-title">{_h(title_b)}</div>
    <div class="vs-meta">{_h(ver_b)}{" &middot; " + _h(date_b) if date_b else ""}</div>
  </div>
</div>

<div class="stat-row">
  <div class="stat-card">
    <div class="stat-num" style="color:#2E7D32">{stats.get("fixed_count",0)}</div>
    <div class="stat-label">Fixed</div>
    <div class="stat-delta" style="color:#2E7D32">&#10003; Resolved</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#C62828">{stats.get("new_count",0)}</div>
    <div class="stat-label">New</div>
    <div class="stat-delta" style="color:#C62828">&#9650; Introduced</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#F57F17">{stats.get("persisting_count",0)}</div>
    <div class="stat-label">Persisting</div>
    <div class="stat-delta" style="color:#F57F17">&#9646; Unresolved</div>
  </div>
  <div class="stat-card">
    <div class="stat-num">{score_a} &#8594; {score_b}</div>
    <div class="stat-label">Security Score</div>
    <div class="stat-delta">{delta_str} change</div>
  </div>
</div>

<div class="tabs">
  <div class="tab active" data-tab="fixed" onclick="showTab('fixed')">
    &#10003; Fixed ({stats.get("fixed_count",0)})
  </div>
  <div class="tab" data-tab="new" onclick="showTab('new')">
    &#9650; New ({stats.get("new_count",0)})
  </div>
  <div class="tab" data-tab="persisting" onclick="showTab('persisting')">
    &#9646; Persisting ({stats.get("persisting_count",0)})
  </div>
</div>

<div id="panel-fixed" class="panel active">
{table_wrap(fixed_rows, "No fixed findings &mdash; no findings from the baseline were resolved.")}
</div>
<div id="panel-new" class="panel">
{table_wrap(new_rows, "No new findings &mdash; no new issues were introduced since the baseline.")}
</div>
<div id="panel-persisting" class="panel">
{table_wrap(persist_rows, "No persisting findings &mdash; all baseline findings have been resolved.")}
</div>

<div class="footer">Generated by Owlet &middot; {_h(gen_ts)}</div>
</div>
<script>{_CMP_JS}</script>
</body>
</html>
""")
    return "".join(p).encode("utf-8")
