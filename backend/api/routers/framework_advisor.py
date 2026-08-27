import json
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Union
from backend.core.ai_providers import get_llm

router = APIRouter(prefix="/frameworks/advisor", tags=["Framework Advisor"])

WIZARD_STEPS = [
    {
        "id": "industry",
        "question": "What industry does your organisation operate in?",
        "hint": "Helps identify industry-specific regulations",
        "multi_select": False,
        "options": [
            "Finance & Banking", "Healthcare", "Government / Public Sector",
            "Retail & E-commerce", "Technology / SaaS", "Manufacturing",
            "Energy & Utilities", "Education",
        ],
    },
    {
        "id": "geography",
        "question": "Where does your organisation operate or store data?",
        "hint": "Data residency determines which regulations apply",
        "multi_select": True,
        "options": [
            "European Union (EU)", "United States", "United Kingdom",
            "India", "Asia-Pacific (APAC)", "Middle East", "Global / Multiple regions",
        ],
    },
    {
        "id": "data_types",
        "question": "What types of sensitive data does your organisation handle?",
        "hint": "Select all that apply",
        "multi_select": True,
        "options": [
            "Payment card data (PAN, CVV)", "Health / medical records",
            "Personal data (PII)", "Government / classified data",
            "Intellectual property / trade secrets", "Financial records", "Employee / HR data",
        ],
    },
    {
        "id": "org_size",
        "question": "How large is your organisation?",
        "hint": "Size affects which frameworks are practical to implement",
        "multi_select": False,
        "options": [
            "Startup (< 50 employees)", "Small (50–250)",
            "Mid-size (250–1,000)", "Large (1,000–5,000)", "Enterprise (5,000+)",
        ],
    },
    {
        "id": "cloud_posture",
        "question": "What is your infrastructure posture?",
        "hint": "Cloud vs. on-premise affects control relevance",
        "multi_select": False,
        "options": [
            "Fully cloud-native (AWS / Azure / GCP)", "Hybrid (cloud + on-premise)",
            "Fully on-premise / data centre", "Multi-cloud",
        ],
    },
    {
        "id": "obligations",
        "question": "Do you have specific compliance obligations or timelines?",
        "hint": "Select all that apply",
        "multi_select": True,
        "options": [
            "Specific audit or certification deadline",
            "Customer / enterprise contract requirement",
            "Regulatory mandate (government / regulator)",
            "Voluntary certification goal",
            "Board / executive directive",
            "No specific obligation yet",
        ],
    },
    {
        "id": "existing_certs",
        "question": "Which frameworks or certifications do you already hold?",
        "hint": "We factor in overlap to reduce your adoption effort",
        "multi_select": True,
        "options": [
            "None yet", "ISO 27001", "SOC 2 Type II", "PCI DSS",
            "NIST CSF", "CIS Controls v8", "HIPAA", "FedRAMP / StateRAMP",
        ],
    },
]

_FALLBACK = {
    "recommendations": [],
    "overlap_insights": [],
    "adoption_sequence": [],
    "summary": "Unable to generate a recommendation at this time. Please check that an AI provider is configured and try again.",
}

_PLATFORM_FRAMEWORKS = {"nist_csf", "cis_v8", "iso_27001", "pci_dss", "gdpr"}


class RecommendRequest(BaseModel):
    answers: dict[str, Union[str, list[str]]]


@router.get("/steps")
def get_steps():
    return {"steps": WIZARD_STEPS}


@router.post("/recommend")
def recommend_frameworks(req: RecommendRequest):
    answers_lines = []
    for step in WIZARD_STEPS:
        val = req.answers.get(step["id"])
        if val:
            display = ", ".join(val) if isinstance(val, list) else val
            answers_lines.append(f"- {step['question']}\n  Answer: {display}")

    answers_text = "\n".join(answers_lines)

    prompt = f"""You are a cybersecurity compliance expert. Based on the following organisation profile, recommend the most applicable security and compliance frameworks.

Organisation Profile:
{answers_text}

Respond with ONLY valid JSON (no markdown, no fences) matching this exact schema:
{{
  "recommendations": [
    {{
      "framework": "<human readable name>",
      "framework_key": "<one of: nist_csf, cis_v8, iso_27001, pci_dss, gdpr, soc2, hipaa, fedramp, nist_800_53, cyber_essentials, mas_trm, or other>",
      "priority": "<mandatory|recommended|optional>",
      "rationale": "<2-3 sentences>",
      "applicable_because": ["<reason 1>", "<reason 2>"],
      "effort": "<low|medium|high>",
      "estimated_controls": <integer>,
      "available_in_platform": <true|false>
    }}
  ],
  "overlap_insights": [
    {{"frameworks": ["<A>", "<B>"], "overlap_pct": <integer 0-100>, "insight": "<one sentence>"}}
  ],
  "adoption_sequence": ["<Framework 1>", "<Framework 2>"],
  "summary": "<2-3 sentence overall recommendation>"
}}

Rules:
- Set available_in_platform: true ONLY for these exact keys: nist_csf, cis_v8, iso_27001, pci_dss, gdpr
- Order recommendations: mandatory first, then recommended, then optional
- Maximum 6 recommendations total
- overlap_insights only when genuine significant control overlap exists (>30%)
- adoption_sequence is the recommended implementation order (most foundational first)
- Be specific to this organisation's profile — not generic advice"""

    try:
        llm = get_llm()
        response = llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        content = content.strip()
        # Strip markdown fences if present
        if content.startswith("```"):
            parts = content.split("```")
            content = parts[1] if len(parts) > 1 else content
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        result = json.loads(content)
        # Enforce available_in_platform correctness
        for rec in result.get("recommendations", []):
            rec["available_in_platform"] = rec.get("framework_key", "") in _PLATFORM_FRAMEWORKS
        return result
    except Exception as exc:
        print(f"[framework_advisor] recommend failed: {exc}")
        return _FALLBACK
