from typing import Dict, Any, Optional, TypedDict, Annotated
from sqlalchemy.orm import Session

from backend.agents.action_agent import ActionAnalysisAgent
from backend.agents.approval_agent import ApprovalOrchestratorAgent
from backend.agents.security_agent import SecurityVerificationAgent
from backend.agents.execution_agent import ExecutionAgent
from backend.models import Action
from backend.schemas import SecurityVerificationResult, ExecutionResult


class AgentSystemState(TypedDict):
    prompt: str
    creator: str
    action_id: Optional[int]
    approval_id: Optional[str]
    structured_action: Optional[Dict[str, Any]]
    canonical_payload: Optional[str]
    payload_hash: Optional[str]
    risk_level: Optional[str]
    risk_explanation: Optional[str]
    token: Optional[str]
    is_approved: bool
    verification_result: Optional[Dict[str, Any]]
    execution_result: Optional[Dict[str, Any]]
    error: Optional[str]


def build_system_graph():
    """
    Constructs the LangGraph state machine orchestrating the secure workflow.
    """
    try:
        from langgraph.graph import StateGraph, END

        workflow = StateGraph(AgentSystemState)

        action_agent = ActionAnalysisAgent()
        approval_agent = ApprovalOrchestratorAgent()
        security_agent = SecurityVerificationAgent()
        execution_agent = ExecutionAgent()

        def analyze_node(state: AgentSystemState) -> Dict[str, Any]:
            res = action_agent.process(state["prompt"], state.get("creator", "alice"))
            return {
                "structured_action": res["structured_action"],
                "canonical_payload": res["canonical_payload"],
                "payload_hash": res["payload_hash"],
                "risk_level": res["risk_level"],
                "risk_explanation": res["risk_explanation"],
            }

        workflow.add_node("analyze", analyze_node)
        workflow.set_entry_point("analyze")
        workflow.add_edge("analyze", END)

        return workflow.compile()
    except Exception:
        # Fallback runner if langgraph is initialized in lightweight mode
        return None


# Global instantiated agent singletons
action_analysis_agent = ActionAnalysisAgent()
approval_orchestrator_agent = ApprovalOrchestratorAgent()
security_verification_agent = SecurityVerificationAgent()
execution_agent_instance = ExecutionAgent()
