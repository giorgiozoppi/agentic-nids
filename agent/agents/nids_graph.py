"""
NIDS LangGraph Workflow

Batch-processing pipeline:

  analyze (ReAct agent + deep-search tool)
      │
      ├─ retry on LLM failure (up to _MAX_RETRIES)
      │
  save_batch (ClickHouse primary, JSONL fallback)
      │
      END
"""
import json
import logging
import operator
from datetime import datetime
from typing import Annotated, Dict, List, Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3


class NIDSBatchState(TypedDict):
    """State for one batch run through the NIDS graph."""
    flows: List[Dict]
    prompt: str
    llm_analysis: Optional[Dict]
    errors: Annotated[List[str], operator.add]
    retry_count: int


# ── Nodes ──────────────────────────────────────────────────────────────────────

async def analyze_batch(state: NIDSBatchState, config: RunnableConfig) -> dict:
    """
    ReAct agent node. The LLM can call `investigate_flows` to search ClickHouse
    for historical traffic context while analyzing the current batch.
    """
    llm = config["configurable"].get("llm")
    store = config["configurable"].get("clickhouse_store")

    if not llm:
        logger.warning("No LLM configured — skipping analysis")
        return {"llm_analysis": {"anomalies": [], "summary": "(no LLM configured)"}}

    tools = []
    if store:
        from agents.deep_search_agent import make_deep_search_tool
        tools = [make_deep_search_tool(llm, store)]

    agent = create_react_agent(llm, tools)
    try:
        result = await agent.ainvoke(
            {"messages": [{"role": "user", "content": state["prompt"]}]}
        )
        messages = result.get("messages", [])
        summary = messages[-1].content if messages else ""
        logger.info("LLM batch analysis completed")
        return {"llm_analysis": {"anomalies": [], "summary": summary}}
    except Exception as exc:
        logger.error(f"LLM analysis failed: {exc}")
        return {"errors": [str(exc)], "retry_count": state["retry_count"] + 1}


async def save_batch(state: NIDSBatchState, config: RunnableConfig) -> dict:
    """
    Persist the batch. Writes to ClickHouse if a store is configured;
    falls back to JSONL if only an output file is set.
    """
    store = config["configurable"].get("clickhouse_store")
    output_file = config["configurable"].get("flows_output_file")
    llm_summary = (state.get("llm_analysis") or {}).get("summary", "")

    if store:
        try:
            store.insert_flows(state["flows"], llm_summary=llm_summary)
        except Exception as exc:
            logger.error(f"ClickHouse insert failed: {exc}")
            return {"errors": [str(exc)]}
    elif output_file:
        try:
            with open(output_file, "a") as fh:
                for flow in state["flows"]:
                    fh.write(json.dumps({**flow, "collected_at": datetime.now().isoformat()}) + "\n")
            logger.info(f"Saved {len(state['flows'])} flows to {output_file} (JSONL fallback)")
        except Exception as exc:
            logger.error(f"JSONL save failed: {exc}")
            return {"errors": [str(exc)]}
    else:
        logger.warning("No storage configured (no ClickHouse store and no output file)")

    return {}


# ── Routing ────────────────────────────────────────────────────────────────────

def route_after_analysis(state: NIDSBatchState) -> str:
    if state.get("llm_analysis") is not None:
        return "save"
    if state["retry_count"] < _MAX_RETRIES:
        logger.info(f"Retrying LLM analysis (attempt {state['retry_count'] + 1}/{_MAX_RETRIES})")
        return "analyze"
    logger.warning("Max LLM retries reached — proceeding without analysis")
    return "save"


# ── Graph ──────────────────────────────────────────────────────────────────────

def build_nids_graph():
    builder = StateGraph(NIDSBatchState)

    builder.add_node("analyze", analyze_batch)
    builder.add_node("save", save_batch)

    builder.add_edge(START, "analyze")
    builder.add_conditional_edges(
        "analyze",
        route_after_analysis,
        {"analyze": "analyze", "save": "save"},
    )
    builder.add_edge("save", END)

    return builder.compile()


nids_graph = build_nids_graph()
