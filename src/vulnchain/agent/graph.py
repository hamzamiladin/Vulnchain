"""LangGraph state machine for the RedTeam scan pipeline."""

from langgraph.graph import END, StateGraph

from vulnchain.agent.nodes import (
    clone_repo_node,
    detect_ai_code_node,
    generate_report_node,
    generate_threat_model_node,
    handle_error_node,
    llm_code_review_node,
    parse_ast_node,
    run_joern_node,
    run_semgrep_node,
    scan_dependencies_node,
    synthesize_attack_chains_node,
)
from vulnchain.agent.state import ScanState


def _route_after_clone(state: ScanState) -> str:
    return "handle_error" if state.get("error") else "parse_ast"


def build_graph() -> StateGraph:
    """Build and compile the RedTeam scan LangGraph state machine.

    Pipeline:
        clone_repo → parse_ast → run_semgrep → detect_ai_code → run_joern
            → scan_dependencies (OSV CVE lookup + tech fingerprint)
            → llm_code_review → generate_threat_model → synthesize_attack_chains
            → generate_report
    """
    graph: StateGraph = StateGraph(ScanState)

    graph.add_node("clone_repo", clone_repo_node)
    graph.add_node("parse_ast", parse_ast_node)
    graph.add_node("run_semgrep", run_semgrep_node)
    graph.add_node("detect_ai_code", detect_ai_code_node)
    graph.add_node("run_joern", run_joern_node)
    graph.add_node("scan_dependencies", scan_dependencies_node)
    graph.add_node("llm_code_review", llm_code_review_node)
    graph.add_node("generate_threat_model", generate_threat_model_node)
    graph.add_node("synthesize_attack_chains", synthesize_attack_chains_node)
    graph.add_node("generate_report", generate_report_node)
    graph.add_node("handle_error", handle_error_node)

    graph.set_entry_point("clone_repo")
    graph.add_conditional_edges("clone_repo", _route_after_clone)
    graph.add_edge("parse_ast", "run_semgrep")
    graph.add_edge("run_semgrep", "detect_ai_code")
    graph.add_edge("detect_ai_code", "run_joern")
    graph.add_edge("run_joern", "scan_dependencies")
    graph.add_edge("scan_dependencies", "llm_code_review")
    graph.add_edge("llm_code_review", "generate_threat_model")
    graph.add_edge("generate_threat_model", "synthesize_attack_chains")
    graph.add_edge("synthesize_attack_chains", "generate_report")
    graph.add_edge("generate_report", END)
    graph.add_edge("handle_error", END)

    return graph.compile()
