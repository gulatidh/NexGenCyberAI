"""Extract structured components + data_flows from uploaded architecture diagrams.

Three input paths, all normalising to the same shape that
`services/threat_modeler.py` consumes:

  - .drawio / .xml  → parsed deterministically via stdlib ElementTree
                      (no LLM call, exact extraction from mxCell graph).
  - .pdf            → text via pypdf; if there's enough extracted text,
                      LLM converts the prose/labels into the JSON shape.
                      Scanned-only PDFs return an error pointing the
                      user at the image-upload path.
  - .jpg / .png     → multimodal LLM (OpenAI vision / Claude vision)
                      reads the diagram pixels and emits the JSON shape.

Output schema (matches threat_modeler.METHODOLOGIES._COMPONENT_FIELDS /
_DATA_FLOW_FIELDS):

  {
    "components": [{id, name, type, trust_zone, criticality, notes}],
    "data_flows": [{from, to, protocol, data, encrypted, notes}],
    "source": "drawio" | "pdf" | "image",
    "warnings": [str, …]
  }
"""
from __future__ import annotations
import base64
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Public dispatch ──────────────────────────────────────────────────────────


SUPPORTED_EXTENSIONS = {".drawio", ".xml", ".pdf", ".jpg", ".jpeg", ".png"}


def detect_kind(filename: str, content_type: Optional[str], data: bytes) -> str:
    """Cheap MIME-sniff. Filename hint first, then content-type, then
    magic-bytes. Returns one of: 'drawio', 'pdf', 'image', or '' (unknown)."""
    lower = (filename or "").lower()
    if lower.endswith(".drawio") or lower.endswith(".xml"):
        return "drawio"
    if lower.endswith(".pdf"):
        return "pdf"
    if lower.endswith((".jpg", ".jpeg", ".png")):
        return "image"
    ct = (content_type or "").lower()
    if "pdf" in ct:
        return "pdf"
    if ct.startswith("image/"):
        return "image"
    if "xml" in ct or "drawio" in ct:
        return "drawio"
    # Magic bytes
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\xff\xd8\xff") or data.startswith(b"\x89PNG"):
        return "image"
    if data.lstrip().startswith(b"<"):
        return "drawio"
    return ""


async def extract(filename: str, content_type: Optional[str], data: bytes) -> Dict[str, Any]:
    """Top-level entry — pick a parser based on file kind."""
    kind = detect_kind(filename, content_type, data)
    if kind == "drawio":
        return parse_drawio(data)
    if kind == "pdf":
        return await parse_pdf(data)
    if kind == "image":
        return await parse_image(data, filename=filename)
    raise ValueError(
        f"Unsupported file type for '{filename}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}"
    )


# ── draw.io / mxGraph XML parser (deterministic) ────────────────────────────


# style → component-type heuristics. mxCell style strings are like
# "rounded=1;whiteSpace=wrap;shape=cylinder3;fillColor=#dae8fc;..."
_TYPE_HINTS = [
    ("cylinder", "database"),
    ("disk", "storage"),
    ("cloud", "endpoint"),
    ("actor", "identity"),
    ("user", "identity"),
    ("lock", "secret-store"),
    ("key", "secret-store"),
    ("queue", "queue"),
    ("server", "vm"),
    ("vm", "vm"),
    ("api", "api"),
]

# Style or label hints → trust zone
_ZONE_LABEL_HINTS = [
    ("public", "public"),
    ("internet", "public"),
    ("dmz", "dmz"),
    ("private", "private"),
    ("internal", "private"),
    ("data tier", "data-tier"),
    ("data-tier", "data-tier"),
    ("management", "management"),
    ("admin", "management"),
]


def _strip_html(s: str) -> str:
    """draw.io labels often contain HTML formatting tags. Strip them."""
    if not s:
        return ""
    s = re.sub(r"<br\s*/?>", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"<[^>]+>", "", s)
    # Decode common HTML entities the cheap way
    s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    return re.sub(r"\s+", " ", s).strip()


def _parse_style(style: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (style or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
        elif part.strip():
            out[part.strip().lower()] = "1"
    return out


def _infer_type(style: str, label: str) -> str:
    s = (style or "").lower() + " " + (label or "").lower()
    for needle, t in _TYPE_HINTS:
        if needle in s:
            return t
    return "other"


def _infer_zone_from_label(label: str) -> Optional[str]:
    l = (label or "").lower()
    for needle, zone in _ZONE_LABEL_HINTS:
        if needle in l:
            return zone
    return None


def parse_drawio(data: bytes) -> Dict[str, Any]:
    """Parse a .drawio / mxfile XML buffer into our normalised JSON.

    Handles two shapes diagrams.net produces:
      - `<mxfile><diagram>...<mxGraphModel>...</mxGraphModel></diagram></mxfile>`
      - `<mxGraphModel>...</mxGraphModel>` directly

    Swimlane / group cells (style includes 'swimlane' or 'group') become
    trust-zone hints; child cells inherit the parent's inferred zone.
    """
    warnings: List[str] = []
    text = data.decode("utf-8", errors="replace").lstrip("﻿").strip()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Diagram XML is malformed: {exc}") from exc

    # diagrams.net sometimes embeds the mxGraphModel as a deflated base64
    # blob inside <diagram>...base64...</diagram> instead of inline XML. If
    # we don't find <mxCell> children, surface that clearly.
    cells = root.findall(".//mxCell")
    if not cells:
        diagram_inner = root.find(".//diagram")
        if diagram_inner is not None and (diagram_inner.text or "").strip() and "<" not in (diagram_inner.text or ""):
            raise ValueError(
                "This .drawio file stores the graph as a compressed payload. "
                "Open it in draw.io and re-save with 'Extras → Edit Diagram → Format: XML' "
                "before uploading."
            )
        raise ValueError("No graph cells found in the diagram.")

    # First pass — collect vertex cells and edge cells. Determine parent
    # relationships so we can map a child's zone to its swimlane parent.
    vertex_by_id: Dict[str, Dict[str, Any]] = {}
    edges_raw: List[Dict[str, Any]] = []
    parent_of: Dict[str, str] = {}

    for cell in cells:
        cid = cell.get("id") or ""
        if not cid or cid in ("0", "1"):
            continue
        parent = cell.get("parent") or "1"
        parent_of[cid] = parent
        is_edge = (cell.get("edge") == "1") or cell.get("source") or cell.get("target")
        is_vertex = cell.get("vertex") == "1"
        style = cell.get("style") or ""
        value = _strip_html(cell.get("value") or "")

        if is_edge:
            edges_raw.append({
                "id": cid,
                "source": cell.get("source") or "",
                "target": cell.get("target") or "",
                "label": value,
                "style": style,
            })
            continue
        if not is_vertex:
            continue
        vertex_by_id[cid] = {
            "id": cid, "label": value, "style": style,
            "is_zone": "swimlane" in style.lower() or "group" in _parse_style(style).get("shape", "").lower(),
        }

    # Resolve trust-zone hint per vertex — walk up parent chain until we
    # hit a swimlane vertex or run out.
    def zone_for(cid: str) -> Optional[str]:
        seen = set()
        p = parent_of.get(cid)
        while p and p not in seen:
            seen.add(p)
            v = vertex_by_id.get(p)
            if v and v.get("is_zone"):
                z = _infer_zone_from_label(v["label"])
                if z:
                    return z
                # Use the swimlane's label literally as the zone
                return _slug_zone(v["label"])
            p = parent_of.get(p)
        return None

    components: List[Dict[str, Any]] = []
    for cid, v in vertex_by_id.items():
        if v["is_zone"]:
            # Don't emit the swimlane itself as a component
            continue
        comp_name = v["label"] or cid
        comp_type = _infer_type(v["style"], v["label"])
        zone = zone_for(cid) or _infer_zone_from_label(v["label"]) or "private"
        components.append({
            "id": _safe_id(cid),
            "name": comp_name[:200],
            "type": comp_type,
            "trust_zone": zone,
            "criticality": "medium",
            "notes": "Extracted from uploaded diagram.",
        })

    # Build id remap so edges reference the same _safe_id values
    id_remap = {v["id"]: _safe_id(v["id"]) for v in vertex_by_id.values() if not v["is_zone"]}

    data_flows: List[Dict[str, Any]] = []
    for e in edges_raw:
        src = id_remap.get(e["source"])
        dst = id_remap.get(e["target"])
        if not src or not dst:
            # Edge points at a swimlane or unknown vertex — skip
            continue
        protocol, encrypted = _infer_protocol(e["label"])
        data_flows.append({
            "from": src,
            "to": dst,
            "protocol": protocol,
            "data": _infer_data(e["label"]),
            "encrypted": encrypted,
            "notes": e["label"][:200] if e["label"] else "",
        })

    if not components:
        warnings.append("No components were extracted — the diagram had only swimlanes/groups.")

    return {
        "components": components,
        "data_flows": data_flows,
        "source": "drawio",
        "warnings": warnings,
    }


_PROTOCOL_HINTS = [
    ("https", ("https", True)),
    ("tls",   ("https", True)),
    ("http",  ("http", False)),
    ("sql",   ("sql", True)),
    ("ssh",   ("ssh", True)),
    ("smb",   ("smb", False)),
    ("grpc",  ("grpc", True)),
    ("amqp",  ("amqp", True)),
    ("kafka", ("amqp", True)),
    ("mqtt",  ("amqp", True)),
    ("ftp",   ("other", False)),
    ("rdp",   ("other", True)),
]


def _infer_protocol(label: str) -> Tuple[str, bool]:
    l = (label or "").lower()
    for needle, (proto, encrypted) in _PROTOCOL_HINTS:
        if needle in l:
            return proto, encrypted
    return "other", True


_DATA_HINTS = [
    ("credential", "credentials"), ("password", "credentials"), ("token", "credentials"),
    ("pii", "pii"), ("personal", "pii"), ("name", "pii"),
    ("payment", "financial"), ("financial", "financial"), ("card", "financial"),
    ("config", "config"), ("setting", "config"),
    ("log", "telemetry"), ("metric", "telemetry"), ("event", "telemetry"),
]


def _infer_data(label: str) -> str:
    l = (label or "").lower()
    for needle, kind in _DATA_HINTS:
        if needle in l:
            return kind
    return "other"


def _slug_zone(label: str) -> str:
    s = (label or "").lower()
    s = re.sub(r"[^a-z0-9-]+", "-", s).strip("-")
    return s or "other"


_ID_RE = re.compile(r"[^A-Za-z0-9_-]")


def _safe_id(cid: str) -> str:
    """draw.io cell IDs can include arbitrary characters; the threat modeler
    expects something tame so JSON keys / mermaid IDs are happy."""
    s = _ID_RE.sub("-", cid or "")
    if not s or not s[0].isalpha():
        s = "n-" + s
    return s[:48]


# ── PDF parser (text-first, LLM-structured) ──────────────────────────────────


_DIAGRAM_EXTRACTION_PROMPT = """You are extracting an architecture / data-flow diagram into structured JSON.

Output STRICT JSON with this exact schema — no prose, no markdown fences:

{
  "components": [
    {"id": "<short-slug>", "name": "<system name>",
     "type": "<vm|storage|identity|repo|endpoint|database|api|queue|secret-store|other>",
     "trust_zone": "<public|dmz|private|data-tier|management>",
     "criticality": "<critical|high|medium|low>", "notes": "<one-line>"}
  ],
  "data_flows": [
    {"from": "<component id>", "to": "<component id>",
     "protocol": "<https|http|sql|ssh|smb|grpc|amqp|other>",
     "data": "<credentials|pii|financial|telemetry|config|other>",
     "encrypted": <true|false>, "notes": "<one-line>"}
  ]
}

Rules:
- Use stable lowercase slug IDs (e.g. "web-app", "auth-svc", "order-db").
- Infer trust_zone from position / labels — Internet-facing = public, DMZ = dmz,
  internal services = private, data stores = data-tier, ops/admin = management.
- If an arrow direction is unclear, set from→to in the direction of data request.
- If you genuinely cannot identify a flow's protocol, use "other" and encrypted=true.
- Empty arrays are valid when nothing of that kind is present.
"""


async def parse_pdf(data: bytes) -> Dict[str, Any]:
    """Extract text from a PDF and ask an LLM to convert it into the diagram
    JSON. Scanned PDFs (no extractable text) return an actionable error."""
    try:
        from pypdf import PdfReader
    except Exception as exc:  # pragma: no cover - pypdf is in requirements
        raise RuntimeError(f"PDF parsing dependency missing: {exc}") from exc

    reader = PdfReader(io.BytesIO(data))
    pages_text: List[str] = []
    for page in reader.pages[:20]:  # 20-page cap protects against giant PDFs
        try:
            pages_text.append(page.extract_text() or "")
        except Exception as exc:
            logger.warning("PDF page extraction failed: %s", exc)
    full_text = "\n\n".join(p.strip() for p in pages_text if p.strip())

    if len(full_text) < 80:
        raise ValueError(
            "Couldn't extract readable text from this PDF — looks like a scanned image. "
            "Export the architecture page as PNG or JPEG and re-upload, or upload the "
            "original .drawio file."
        )

    structured = await _llm_extract_diagram(
        prompt_context=f"Architecture diagram (from PDF):\n\n{full_text[:8000]}",
        modality="text",
    )
    structured["source"] = "pdf"
    return structured


# ── Image parser (multimodal LLM) ────────────────────────────────────────────


async def parse_image(data: bytes, *, filename: str = "") -> Dict[str, Any]:
    """Vision-LLM extraction. Sends the image to the configured provider
    (OpenAI gpt-4o, Claude, Gemini all accept image inputs) and parses the
    returned JSON."""
    mime = "image/png" if filename.lower().endswith(".png") else "image/jpeg"
    b64 = base64.b64encode(data).decode("ascii")
    image_url = f"data:{mime};base64,{b64}"
    structured = await _llm_extract_diagram(
        prompt_context="Extract the architecture diagram in the attached image.",
        modality="image",
        image_url=image_url,
    )
    structured["source"] = "image"
    return structured


# ── Shared LLM call ──────────────────────────────────────────────────────────


async def _llm_extract_diagram(
    *,
    prompt_context: str,
    modality: str,
    image_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Common LLM round-trip — same JSON schema enforced regardless of input
    modality. Reuses core.ai_providers.get_llm so the operator's configured
    provider/model is honoured."""
    try:
        from core.ai_providers import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = get_llm(temperature=0.1, max_tokens=2048)
    except Exception as exc:
        raise RuntimeError(f"AI provider unavailable for diagram extraction: {exc}") from exc

    if modality == "image" and image_url:
        human = HumanMessage(content=[
            {"type": "text", "text": prompt_context},
            {"type": "image_url", "image_url": {"url": image_url}},
        ])
    else:
        human = HumanMessage(content=prompt_context)

    try:
        result = await llm.ainvoke([SystemMessage(content=_DIAGRAM_EXTRACTION_PROMPT), human])
    except Exception as exc:
        raise RuntimeError(f"Diagram extraction LLM call failed: {exc}") from exc

    text = result.content if hasattr(result, "content") else str(result)
    if isinstance(text, list):
        text = "\n".join(str(p) for p in text)
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    try:
        start = text.find("{")
        end = text.rfind("}")
        parsed = json.loads(text[start:end + 1]) if start >= 0 and end > start else {}
    except Exception as exc:
        raise RuntimeError(f"LLM did not return parseable JSON: {exc}") from exc

    components_raw = parsed.get("components") or []
    flows_raw = parsed.get("data_flows") or []
    components = [_norm_component(c) for c in components_raw[:60]]
    known_ids = {c["id"] for c in components}
    data_flows = []
    for f in flows_raw[:80]:
        nf = _norm_flow(f)
        if nf["from"] in known_ids and nf["to"] in known_ids:
            data_flows.append(nf)

    return {
        "components": components,
        "data_flows": data_flows,
        "warnings": [] if components else ["LLM extracted zero components — the diagram may not be an architecture diagram."],
    }


_VALID_ZONES = {"public", "dmz", "private", "data-tier", "management", "other"}
_VALID_TYPES = {"vm", "storage", "identity", "repo", "endpoint", "database", "api", "queue", "secret-store", "other"}
_VALID_CRIT = {"critical", "high", "medium", "low"}
_VALID_PROTOCOL = {"https", "http", "sql", "ssh", "smb", "grpc", "amqp", "other"}
_VALID_DATA = {"credentials", "pii", "financial", "telemetry", "config", "other"}


def _norm_component(c: Dict[str, Any]) -> Dict[str, Any]:
    cid = _safe_id(str(c.get("id") or c.get("name") or ""))
    zone = str(c.get("trust_zone") or "private").lower().strip()
    if zone not in _VALID_ZONES:
        zone = "private"
    ctype = str(c.get("type") or "other").lower().strip()
    if ctype not in _VALID_TYPES:
        ctype = "other"
    crit = str(c.get("criticality") or "medium").lower().strip()
    if crit not in _VALID_CRIT:
        crit = "medium"
    return {
        "id": cid or "n-unknown",
        "name": str(c.get("name") or cid or "unnamed")[:200],
        "type": ctype,
        "trust_zone": zone,
        "criticality": crit,
        "notes": str(c.get("notes") or "")[:200],
    }


def _norm_flow(f: Dict[str, Any]) -> Dict[str, Any]:
    proto = str(f.get("protocol") or "other").lower().strip()
    if proto not in _VALID_PROTOCOL:
        proto = "other"
    data = str(f.get("data") or "other").lower().strip()
    if data not in _VALID_DATA:
        data = "other"
    encrypted = f.get("encrypted", True)
    if isinstance(encrypted, str):
        encrypted = encrypted.lower() not in ("false", "0", "no", "")
    return {
        "from": _safe_id(str(f.get("from") or "")),
        "to": _safe_id(str(f.get("to") or "")),
        "protocol": proto,
        "data": data,
        "encrypted": bool(encrypted),
        "notes": str(f.get("notes") or "")[:200],
    }
