# Security Ontology / Asset-Centric View — Implementation Plan

## Problem

Correlation data already exists across models but is unlinked:

| Model | Correlation key |
|---|---|
| `Finding` | `resource_id`, `resource_type`, `cve_id`, `control_id`, `control_mappings` |
| `Asset` | `resource_id`, `name`, `ip_address`, `hostname` |
| `ThreatEntry` | `techniques` (MITRE ATT&CK), `scan_id` |
| `Risk` | `category`, `domain` |
| `ControlDeficiency` | `control_id`, `framework` |

`Finding.resource_id` often equals `Asset.resource_id` (EC2 ID, hostname, IP) but there is no FK between them. Everything lives in separate islands. Analysts must manually cross-reference.

---

## Phase 1 — Schema linkage (1–2 days)

**Backend changes:**

1. Add nullable `asset_id` FK column to `Finding`, `Risk`, `ThreatEntry` via `_ensure_added_columns()` in `main.py`.

2. Create `backend/services/asset_correlator.py`:
   - `correlate_findings_to_assets(db, client_id, scan_id)` — fuzzy-matches `Finding.resource_id` against `Asset.resource_id`, `Asset.hostname`, `Asset.ip_address` for the same client.
   - Match priority: exact `resource_id` → exact `hostname` → exact `ip_address`.
   - Sets `finding.asset_id` in bulk where a match is found.
   - Does NOT overwrite manually set `asset_id`.

3. Call `correlate_findings_to_assets()` at the end of `_execute_scan` in `scans.py` after findings are written to DB. Also expose as `POST /clients/{cid}/assets/correlate` for manual re-run.

**Why this first:** Everything in Phases 2–4 depends on this linkage being accurate. Without it the graph and detail pages show empty data.

---

## Phase 2 — Enhanced Asset Detail page (1–2 days)

**Backend:**
- New endpoint: `GET /clients/{cid}/assets/{aid}/summary`
- Returns:
  ```json
  {
    "asset": { ...asset fields... },
    "findings": { "total": 12, "critical": 2, "high": 4, "items": [...] },
    "risks": { "total": 3, "items": [...] },
    "threats": { "total": 5, "items": [...] },
    "cves": [
      { "cve_id": "CVE-2021-44228", "cvss": 10.0, "finding_count": 3, "status": "open" }
    ],
    "controls": { "passed": 8, "failed": 4, "items": [...] }
  }
  ```

**Frontend — `AssetDetail.tsx`:**
- Add tabs: Overview · Findings · Risks · Threats · CVEs · Controls
- Overview tab: severity donut, risk score gauge, top CVEs, MITRE techniques heatmap
- Findings tab: reuse `FindingRow` pattern, filterable by severity/status
- CVE tab: table of CVEs affecting this asset, CVSS score, finding count, remediation status
- Threats tab: MITRE technique chips linked to ThreatEntry rows

---

## Phase 3 — CVE pivot page (1 day)

**Backend:**
- `GET /clients/{cid}/cve/{cve_id}` — returns:
  - All assets affected (via findings with this CVE ID)
  - All findings (across all assets)
  - CVSS score (from `Finding.cvss_score`, take max)
  - Remediation status summary (open / remediated counts)

**Frontend — `CVEDetail.tsx`:**
- Accessible by clicking any CVE chip anywhere in the app (`navigate(\`/vulnerability/cve/${cveId}\`)`)
- Header: CVE ID, CVSS badge, severity chip
- Two panels: Affected Assets (list with finding count per asset) + All Findings (table)
- "View on NVD" external link

Add CVE chips as clickable in `FindingDetail`, `AssetDetail`, `ThreatRegister`.

---

## Phase 4 — Ontology graph view (2–3 days)

**Package:** `react-force-graph` (already lightweight, WebGL-backed) or extend existing `AttackPaths.tsx` SVG pattern.

**Backend:**
- `GET /clients/{cid}/ontology/graph?asset_id=&severity=&framework=` — returns `{ nodes, edges }`
- Node types: `asset` (blue), `finding` (red/orange by severity), `cve` (purple), `threat` (yellow), `control` (green)
- Edge types: `has-finding`, `exploits-cve`, `maps-to-control`, `linked-to-threat`, `mitigated-by`

**Frontend — `OntologyGraph.tsx`:**
- Filter bar: asset selector, severity filter, MITRE phase filter, framework filter
- Clicking a node opens a side panel with the entity's detail summary
- Toggle between graph view and table view (same data, different presentation)
- Export as PNG

**Route:** `/intelligence/ontology` — add to `INTELLIGENCE` product nav in `products/index.tsx`.

---

## What NOT to do

- Do not build the graph (Phase 4) before the data linkage (Phase 1) is accurate — an empty or sparse graph is worse than no graph.
- Do not create new join tables — nullable FKs on existing tables + correlation service is sufficient.
- Do not try to auto-link 100% of findings — `resource_id` matching covers ~80%; manual asset tagging on the Finding PATCH endpoint covers the rest.
- Do not add `asset_id` to the scan import flow on day one — get the auto-correlator working first, then retrofit import.

---

## Ship order

```
Phase 1 (linkage) → Phase 2 (Asset Detail) → Phase 3 (CVE pivot) → Phase 4 (graph)
```

Phase 1+2 alone is immediately useful to analysts. Phase 3+4 can ship independently after that.

---

## Key files to touch

| File | Change |
|---|---|
| `backend/main.py` | `_ensure_added_columns()` — add `asset_id` to findings, risks, threat_entries |
| `backend/api/models/models.py` | Add `asset_id` FK + relationship on Finding, Risk, ThreatEntry |
| `backend/services/asset_correlator.py` | New — correlation logic |
| `backend/api/routers/scans.py` | Call correlator after scan completion |
| `backend/api/routers/assets.py` | New endpoints: `/assets/{aid}/summary`, `/assets/correlate`, `/cve/{cve_id}` |
| `frontend/src/pages/AssetDetail.tsx` | Add tabbed summary view |
| `frontend/src/pages/CVEDetail.tsx` | New — CVE pivot page |
| `frontend/src/pages/OntologyGraph.tsx` | New — graph view |
| `frontend/src/products/index.tsx` | Add OntologyGraph to INTELLIGENCE nav |
| `frontend/src/App.tsx` | Wire new routes |
