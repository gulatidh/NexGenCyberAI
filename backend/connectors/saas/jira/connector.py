"""
NexGenCyberAI - Jira Connector
Creates and reads issues via Jira REST API v3.
Auth: Basic (email + API token) or OAuth.
Credentials: base_url, email, api_token, project_key (default project).
"""
from typing import Any, Dict, List
import httpx
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult, FindingSeverity

# Jira priority names → our severity labels (reverse map used below)
_SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


def _adf(text: str) -> Dict:
    """Wrap plain text in Atlassian Document Format (ADF)."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": text}],
            }
        ],
    }


class JiraConnector(BaseConnector):

    @property
    def _base_url(self) -> str:
        url = self.credentials.get("url") or self.credentials.get("base_url", "")
        if not url:
            raise ValueError("Jira URL is not configured — set 'url' in the connector credentials")
        return url.rstrip("/")

    def _auth(self):
        return (self.credentials["email"], self.credentials["api_token"])

    async def _get(self, path: str, params: Dict = {}) -> Dict:
        url = f"{self._base_url}{path}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            resp = await client.get(url, auth=self._auth(), params=params)
        resp.raise_for_status()
        return resp.json()

    async def _post(self, path: str, payload: Dict) -> Dict:
        url = f"{self._base_url}{path}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            resp = await client.post(
                url,
                auth=self._auth(),
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        resp.raise_for_status()
        return resp.json()

    async def test_connection(self) -> ConnectorTestResult:
        try:
            data = await self._get("/rest/api/3/myself")
            return ConnectorTestResult(
                success=True,
                message=f"Jira connection successful — logged in as {data.get('displayName', 'unknown')}",
                details=data,
            )
        except Exception as exc:
            return ConnectorTestResult(success=False, message=str(exc))

    async def create_issue(
        self,
        title: str,
        description: str,
        severity: str,
        issue_type: str = "Bug",
        project_key: str | None = None,
    ) -> Dict[str, Any]:
        """Create a Jira issue and return {id, key, url}."""
        pkey = project_key or self.credentials.get("project_key", "")
        if not pkey:
            raise ValueError("project_key is required — set it in connector config or pass explicitly")
        priority_name = _SEVERITY_TO_PRIORITY.get(severity.lower(), "Medium")
        payload = {
            "fields": {
                "summary": title[:255],
                "description": _adf(description),
                "issuetype": {"name": issue_type},
                "priority": {"name": priority_name},
                "project": {"key": pkey},
            }
        }
        data = await self._post("/rest/api/3/issue", payload)
        issue_id = data.get("id", "")
        issue_key = data.get("key", "")
        url = f"{self._base_url}/browse/{issue_key}" if issue_key else ""
        return {"id": issue_id, "key": issue_key, "url": url}

    async def get_issue_status(self, issue_key: str) -> Dict[str, Any]:
        """Return current {status, summary, url} for a given issue key."""
        data = await self._get(
            f"/rest/api/3/issue/{issue_key}",
            {"fields": "status,summary"},
        )
        fields = data.get("fields", {})
        status = fields.get("status", {}).get("name", "")
        summary = fields.get("summary", "")
        url = f"{self._base_url}/browse/{issue_key}"
        return {"status": status, "summary": summary, "url": url}

    async def get_resources(self) -> List[Dict[str, Any]]:
        return []

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
