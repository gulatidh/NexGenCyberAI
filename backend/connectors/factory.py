"""
NexGenCyberAI - Connector Factory
Returns the right connector class given a ConnectorType.
"""
from typing import Any, Dict
from ..api.models.models import ConnectorType
from .base import BaseConnector
from .azure.connector import AzureConnector
from .aws.connector import AWSConnector
from .gcp.connector import GCPConnector
from .onprem.connector import OnPremConnector
from .entraid.connector import EntraIDConnector
from .containers.connector import ContainerConnector
from .saas.servicenow.connector import ServiceNowConnector
from .saas.okta.connector import OktaConnector


_REGISTRY = {
    ConnectorType.AZURE: AzureConnector,
    ConnectorType.AWS: AWSConnector,
    ConnectorType.GCP: GCPConnector,
    ConnectorType.ONPREM: OnPremConnector,
    ConnectorType.ENTRAID: EntraIDConnector,
    ConnectorType.CONTAINERS: ContainerConnector,
    ConnectorType.SERVICENOW: ServiceNowConnector,
    ConnectorType.OKTA: OktaConnector,
}


def get_connector(
    connector_type: ConnectorType,
    credentials: Dict[str, Any],
    config: Dict[str, Any],
) -> BaseConnector:
    cls = _REGISTRY.get(connector_type)
    if cls is None:
        raise ValueError(f"No connector registered for type: {connector_type}")
    return cls(credentials=credentials, config=config)
