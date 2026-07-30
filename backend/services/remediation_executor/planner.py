"""LLM-powered remediation plan generator.

Takes a list of Finding ORM objects and returns a structured plan dict:
{
    "findings": [
        {
            "finding_id": "<uuid>",
            "confidence_score": <int 0-100>,
            "automatable": "<yes|partial|no>",
            "estimated_downtime": "<none|minimal|maintenance_window>",
            "risk_level": "<low|medium|high>",
            "step_by_step_plan": ["step 1", ...],
            "artifact_type": "<bash|powershell|aws_cli|azure_cli|terraform|code_patch|manual>",
            "artifact_content": "<executable script or manual instructions>",
            "what_could_go_wrong": "...",
            "rollback_steps": ["rollback step 1", ...]
        },
        ...
    ],
    "overall_summary": "...",
    "recommended_order": ["<finding_id>", ...]
}
"""
import json
import logging
from langchain_core.messages import HumanMessage, SystemMessage

logger = logging.getLogger(__name__)

_SYSTEM = """You are a senior security engineer generating precise, executable remediation artifacts for security findings.

For each finding produce a remediation plan. Output MUST be valid JSON — no prose, no markdown, only the JSON object.

Required schema:
{
  "findings": [
    {
      "finding_id": "<uuid string>",
      "confidence_score": <integer 0-100>,
      "automatable": "<yes|partial|no>",
      "estimated_downtime": "<none|minimal|maintenance_window>",
      "risk_level": "<low|medium|high>",
      "step_by_step_plan": ["<step>", ...],
      "artifact_type": "<bash|powershell|aws_cli|azure_cli|terraform|code_patch|manual>",
      "artifact_content": "<full executable script or manual instructions>",
      "what_could_go_wrong": "<concise risk description>",
      "rollback_steps": ["<step>", ...]
    }
  ],
  "overall_summary": "<2-3 sentences summarising the batch>",
  "recommended_order": ["<finding_id>", ...]
}

Artifact type rules:
- bash: Linux/Unix hosts, apt/yum/pip package updates, firewall rules (ufw/iptables), file permissions, service config
- powershell: Windows hosts, AD, registry, Windows services, IIS
- aws_cli: AWS resources — EC2, S3, IAM, Security Groups, RDS, CloudTrail
- azure_cli: Azure resources — VMs, NSGs, Storage, Entra ID, Key Vault
- terraform: When the finding is an IaC drift issue; show the corrected HCL block
- code_patch: Application code vulnerabilities — output as unified diff (--- a/file +++ b/file)
- manual: Cannot be scripted — org policy, licensing, requires human judgment or physical action

Confidence scoring:
- 90-100: Known CVE with published patch command, single-line config fix, well-documented remediation
- 70-89: Standard misconfiguration with documented remediation requiring minor env-specific adaptation
- 50-69: Fix is clear but command parameters depend on undisclosed environment details
- below 50: Highly context-dependent; mark automatable="no"

Rules:
- Use actual commands. Do not use placeholders like <YOUR_REGION> if the resource_id contains enough context to infer them.
- For CVEs, include the exact package name and minimum safe version.
- recommended_order: critical/high severity first, then group by resource to minimise context switches.
- risk_level reflects the risk of APPLYING the fix, not the severity of the vulnerability.
"""


def _finding_block(f) -> str:
    lines = [
        f"finding_id: {f.id}",
        f"title: {f.title}",
        f"severity: {f.severity}",
        f"resource_id: {f.resource_id or 'unknown'}",
        f"resource_type: {f.resource_type or 'unknown'}",
    ]
    if getattr(f, "description", None):
        lines.append(f"description: {(f.description or '')[:800]}")
    if getattr(f, "cve_id", None):
        lines.append(f"cve_id: {f.cve_id}")
    if getattr(f, "cvss_score", None):
        lines.append(f"cvss_score: {f.cvss_score}")
    if getattr(f, "remediation", None):
        lines.append(f"vendor_remediation_hint: {(f.remediation or '')[:600]}")
    if getattr(f, "evidence", None) and isinstance(f.evidence, dict):
        lines.append(f"evidence: {json.dumps(f.evidence, default=str)[:400]}")
    return "\n".join(lines)


async def generate_remediation_plan(findings: list) -> dict:
    from core.ai_providers import get_llm, ProviderUnavailableError

    if not findings:
        return {"findings": [], "overall_summary": "No findings provided.", "recommended_order": []}

    blocks = "\n\n---\n\n".join(_finding_block(f) for f in findings)
    user_prompt = f"Generate a remediation plan for these {len(findings)} finding(s):\n\n{blocks}"

    try:
        llm = get_llm(temperature=0.1, max_tokens=8192)
        resp = llm.invoke([SystemMessage(content=_SYSTEM), HumanMessage(content=user_prompt)])
        raw = resp.content.strip()

        # Strip ```json ... ``` fences if present
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        plan = json.loads(raw)

        # Compute derived aggregates
        fp = plan.get("findings", [])
        if fp:
            scores = [p.get("confidence_score", 0) for p in fp]
            plan["overall_confidence"] = round(sum(scores) / len(scores), 1)
            risk_order = {"high": 3, "medium": 2, "low": 1}
            plan["overall_risk_level"] = max(
                (p.get("risk_level", "low") for p in fp),
                key=lambda r: risk_order.get(r, 0),
                default="low",
            )
        return plan

    except (json.JSONDecodeError, AttributeError, KeyError) as exc:
        logger.error("Planner: LLM returned invalid JSON — %s", exc)
        return _fallback_plan(findings)
    except Exception as exc:
        logger.error("Planner: unexpected error — %s", exc, exc_info=True)
        raise


def _fallback_plan(findings) -> dict:
    return {
        "findings": [
            {
                "finding_id": str(f.id),
                "confidence_score": 0,
                "automatable": "no",
                "estimated_downtime": "unknown",
                "risk_level": "high",
                "step_by_step_plan": ["AI plan generation failed — manual review required."],
                "artifact_type": "manual",
                "artifact_content": getattr(f, "remediation", None) or "No automated remediation available.",
                "what_could_go_wrong": "Plan generation failed.",
                "rollback_steps": ["N/A"],
            }
            for f in findings
        ],
        "overall_summary": "Plan generation failed. Manual review required.",
        "overall_confidence": 0,
        "overall_risk_level": "high",
        "recommended_order": [str(f.id) for f in findings],
    }
