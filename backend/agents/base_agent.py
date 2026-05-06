"""
NexGenCyberAI - Base AI Agent
All agents share a provider-agnostic LangChain foundation.
The provider (Claude / OpenAI / Gemini / Bedrock / Azure OpenAI) is
resolved at runtime from the request or from DEFAULT_AI_PROVIDER.
"""
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferWindowMemory
from typing import Any, Dict, List, Optional
from core.ai_providers import get_llm, AIProvider
from core.config import get_settings
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


REACT_PROMPT = PromptTemplate.from_template(
    """You are {agent_name}, a cybersecurity AI agent specialised in {domain}.
Your job: {objective}

You have access to the following tools:
{tools}

Use this format strictly:
Thought: (reason about the current situation)
Action: (one of [{tool_names}])
Action Input: (the input to the action)
Observation: (result of the action)
... (repeat Thought/Action/Observation as needed)
Thought: I now have enough information to answer.
Final Answer: (your comprehensive, structured response)

Begin!

Context provided:
{input}

{agent_scratchpad}
"""
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
        self.memory = ConversationBufferWindowMemory(k=5, memory_key="chat_history")
        self._executor: Optional[AgentExecutor] = None

    def _get_llm(self):
        return get_llm(provider=self._provider, model=self._model)

    def _default_tools(self) -> List[Tool]:
        return []

    def _build_executor(self) -> AgentExecutor:
        llm = self._get_llm()
        prompt = REACT_PROMPT.partial(
            agent_name=self.agent_name,
            domain=self.domain,
            objective=self.objective,
        )
        agent = create_react_agent(llm, self.tools, prompt)
        return AgentExecutor(
            agent=agent,
            tools=self.tools,
            memory=self.memory,
            verbose=True,
            max_iterations=10,
            handle_parsing_errors=True,
        )

    def set_provider(self, provider: str, model: Optional[str] = None):
        """Switch AI provider at runtime (called per-request if client has a preference)."""
        self._provider = provider
        self._model = model
        self._executor = None  # force rebuild with new provider

    async def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        provider_label = self._provider or settings.DEFAULT_AI_PROVIDER
        # Check if any AI provider is configured
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
            if self._executor is None:
                self._executor = self._build_executor()
            result = self._executor.invoke({"input": str(input_data)})
            return {
                "output": result.get("output", ""),
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
