from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph


class AdvisoryGraphState(TypedDict, total=False):
    advisory: dict[str, Any]
    result: Any
    skip_git: bool


def build_langgraph_advisory_graph(analyzer):
    graph = StateGraph(AdvisoryGraphState)

    def analyze_node(state: AdvisoryGraphState) -> AdvisoryGraphState:
        result = analyzer.analyze(state["advisory"], skip_git=bool(state.get("skip_git")))
        return {**state, "result": result}

    graph.add_node("analyze", analyze_node)
    graph.add_edge(START, "analyze")
    graph.add_edge("analyze", END)
    return graph.compile()


class LangGraphAnalyzer:
    def __init__(self, analyzer):
        self.graph = build_langgraph_advisory_graph(analyzer)

    def analyze(self, advisory: dict, skip_git: bool = False):
        result = self.graph.invoke({"advisory": advisory, "skip_git": skip_git})
        return result["result"]
