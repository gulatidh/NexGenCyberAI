"""
NexGenCyberAI - Connector Factory
Returns the right connector class given a ConnectorType.
"""
from typing import Any, Dict
from api.models.models import ConnectorType
from connectors.base import BaseConnector
from connectors.azure.connector import AzureConnector
from connectors.aws.connector import AWSConnector
from connectors.gcp.connector import GCPConnector
from connectors.onprem.connector import OnPremConnector
from connectors.entraid.connector import EntraIDConnector
from connectors.containers.connector import ContainerConnector
from connectors.saas.servicenow.connector import ServiceNowConnector
from connectors.saas.okta.connector import OktaConnector
from connectors.web.connector import WebConnector


_REGISTRY = {
    ConnectorType.AZURE: AzureConnector,
    ConnectorType.AWS: AWSConnector,
    ConnectorType.GCP: GCPConnector,
    ConnectorType.ONPREM: OnPremConnector,
    ConnectorType.ENTRAID: EntraIDConnector,
    ConnectorType.CONTAINERS: ContainerConnector,
    ConnectorType.SERVICENOW: ServiceNowConnector,
    ConnectorType.OKTA: OktaConnector,
    ConnectorType.WEB: WebConnector,
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
