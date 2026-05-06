"""
NexGenCyberAI - Base AI Agent
All agents share a provider-agnostic LangChain/LangGraph foundation.
The provider (Claude / OpenAI / Gemini / Bedrock / Azure OpenAI) is
resolved at runtime from the request or from DEFAULT_AI_PROVIDER.
"""
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import Tool
from langchain_core.messages import HumanMessage, SystemMessage
from typing import Any, Dict, List, Optional
from core.ai_providers import get_llm, AIProvider
from core.config import get_settings
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


def _build_system_prompt(agent_name: str, domain: str, objective: str) -> str:
    return (
        f"You are {agent_name}, a cybersecurity AI agent specialised in {domain}.\n"
        f"Your job: {objective}\n\n"
        "When analysing, reason step by step. Provide a structured, comprehensive response. "
        "Use the available tools as needed to gather information before answering."
    )


class BaseAgent:
    agent_name: str = "BaseAgent"
    domain: str = "cybersecurity"
    objective: str = "assist with cybersecurity tasks"

    def __init__(
        self,
        tools: Optional[List[Tool]] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self._provider = provider
        self._model = model
        self.tools = tools or self._default_tools()
        self._agent = None

    def _get_llm(self):
        return get_llm(provider=self._provider, model=self._model)

    def _default_tools(self) -> List[Tool]:
        return []

    def _build_agent(self):
        llm = self._get_llm()
        system_prompt = _build_system_prompt(self.agent_name, self.domain, self.objective)
        return create_react_agent(llm, self.tools, prompt=system_prompt)

    def set_provider(self, provider: str, model: Optional[str] = None):
        """Switch AI provider at runtime (called per-request if client has a preference)."""
        self._provider = provider
        self._model = model
        self._agent = None  # force rebuild with new provider

    async def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        provider_label = self._provider or settings.DEFAULT_AI_PROVIDER
        has_provider = any([
            settings.AZURE_OPENAI_API_KEY,
            settings.OPENAI_API_KEY,
            settings.ANTHROPIC_API_KEY,
            settings.GOOGLE_API_KEY,
            settings.AWS_BEDROCK_REGION,
        ])
        if not has_provider:
            return await self._fallback_analysis(input_data)
        try:
            if self._agent is None:
                self._agent = self._build_agent()
            result = self._agent.invoke({"messages": [HumanMessage(content=str(input_data))]})
            # Extract the last AI message as output
            messages = result.get("messages", [])
            output = messages[-1].content if messages else ""
            return {
                "output": output,
                "success": True,
                "provider": provider_label,
            }
        except Exception as exc:
            logger.error(f"{self.agent_name} [{provider_label}] error: {exc}")
            return {"output": str(exc), "success": False, "error": str(exc), "provider": provider_label}

    async def _fallback_analysis(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "output": (
                "Rule-based analysis only. "
                "Configure an AI provider (Claude/OpenAI/Gemini/Bedrock) for AI-powered insights."
            ),
            "success": True,
            "fallback": True,
            "provider": "none",
        }
