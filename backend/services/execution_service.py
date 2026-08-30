import datetime
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from backend.models import Action, Approval
from backend.schemas import ExecutionResult, SecurityVerificationResult
from backend.agents.graph import security_verification_agent, execution_agent_instance
from backend.services.audit_service import log_event


def resume_and_execute_action(
    db: Session,
    action_id: int,
    provided_token: Optional[str] = None,
    simulated_now: Optional[datetime.datetime] = None,
) -> ExecutionResult:
    """
    Workflow:
    RESUME -> RE-VALIDATE EVERYTHING (9 Security Checks) -> EXECUTE OR REFUSE
    """
    # 1. Log resume event
    log_event(
        db=db,
        stage="RESUME",
        agent_name="Security Verification Agent",
        status="INFO",
        details=f"Resume requested for Action #{action_id}. Beginning deterministic 9-point security protocol re-verification.",
        action_id=action_id,
    )

    # 2. Security Verification Agent performs deterministic validation
    verification_result: SecurityVerificationResult = security_verification_agent.verify(
        db=db,
        action_id=action_id,
        provided_token=provided_token,
        simulated_now=simulated_now,
    )

    # 3. Execution Agent acts based on deterministic outcome
    execution_res = execution_agent_instance.execute(
        db=db,
        action_id=action_id,
        verification_result=verification_result,
    )

    return execution_res


def verify_action_security_only(
    db: Session,
    action_id: int,
    provided_token: Optional[str] = None,
    simulated_now: Optional[datetime.datetime] = None,
) -> SecurityVerificationResult:
    """Performs read-only deterministic 9-point verification check."""
    return security_verification_agent.verify(
        db=db,
        action_id=action_id,
        provided_token=provided_token,
        simulated_now=simulated_now,
    )
