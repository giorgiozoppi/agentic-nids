"""
Deep Search Agent

A ReAct sub-agent with five ClickHouse search tools, exposed as a single
`investigate_flows` tool so the main analysis agent can call it to look up
historical traffic patterns during threat analysis.
"""
import logging

from langchain_core.language_models import BaseChatModel
from langchain_core.tools import tool
from langchain.agents import create_agent

from agents.storage.clickhouse_store import ClickHouseFlowStore
from agents.tools.flow_search_tools import make_flow_search_tools

logger = logging.getLogger(__name__)


def make_deep_search_tool(llm: BaseChatModel, store: ClickHouseFlowStore):
    """
    Build the deep-search sub-agent and wrap it as a single LangChain tool.

    The returned tool can be passed to any other agent so that it can query
    ClickHouse using natural-language investigation requests.
    """
    search_tools = make_flow_search_tools(store)
    agent = create_agent(
        llm,
        search_tools,
        system_prompt=(
            "You are a network forensics analyst with access to a historical flow database. "
            "Use the available tools to investigate the user's query thoroughly. "
            "Always call at least one tool before answering. "
            "Return a concise, structured summary of your findings."
        ),
    )

    @tool
    async def investigate_flows(query: str) -> str:
        """
        Investigate network flows stored in the historical ClickHouse database.
        Use this to look up past traffic for a suspicious IP, port, or application,
        or to retrieve aggregate statistics. Provide a natural-language query such as:
        'find all flows from 10.0.0.5 in the last hour' or 'show top talkers'.
        """
        logger.info(f"Deep-search agent invoked: {query[:80]}")
        result = await agent.ainvoke({"messages": [{"role": "user", "content": query}]})
        messages = result.get("messages", [])
        if not messages:
            return "No investigation results found."
        return messages[-1].content

    return investigate_flows
