"""Tenable.io connector — test connection via pytenable SDK."""
import logging
from typing import Any, Dict, List
from connectors.base import BaseConnector, ConnectorFinding, ConnectorTestResult

logger = logging.getLogger(__name__)


class TenableConnector(BaseConnector):

    async def test_connection(self) -> ConnectorTestResult:
        access_key = self.credentials.get("access_key", "")
        secret_key = self.credentials.get("secret_key", "")
        if not access_key or not secret_key:
            return ConnectorTestResult(success=False, message="Tenable.io requires 'access_key' and 'secret_key'")
        try:
            import asyncio
            from tenable.io import TenableIO

            def _check():
                tio = TenableIO(access_key, secret_key)
                me = tio.users.list()
                users = list(me)
                return len(users)

            count = await asyncio.to_thread(_check)
            return ConnectorTestResult(
                success=True,
                message="Connected to Tenable.io successfully",
                details={"users": count},
            )
        except ImportError:
            return ConnectorTestResult(success=False, message="pytenable package not installed on server")
        except Exception as exc:
            msg = str(exc)
            if "401" in msg or "403" in msg or "authentication" in msg.lower():
                return ConnectorTestResult(success=False, message="Authentication failed — check access_key and secret_key")
            return ConnectorTestResult(success=False, message=f"Tenable connection error: {exc}")

    async def get_resources(self) -> List[Dict[str, Any]]:
        return []

    async def run_configuration_review(self) -> List[ConnectorFinding]:
        return []

    async def run_vulnerability_scan(self) -> List[ConnectorFinding]:
        return []

    async def get_compliance_status(self, framework: str) -> Dict[str, Any]:
        return {}
