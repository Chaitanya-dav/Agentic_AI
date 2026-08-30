from typing import Tuple, Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.models import Approval, Action
from backend.agents.graph import approval_orchestrator_agent
from backend.services.audit_service import log_event


def claim_approval(db: Session, approval_id: str, approver_id: str) -> Tuple[bool, str]:
    """Claims an approval request on behalf of an approver."""
    approval = db.query(Approval).filter(Approval.approval_id == approval_id).first()
    if not approval:
        return False, f"Approval '{approval_id}' not found."

    creator_norm = (approval.creator_id or "").strip().lower()
    approver_norm = (approver_id or "").strip().lower()

    if creator_norm == approver_norm:
        return False, f"Four-Eyes Violation: Initiator '{creator_norm}' cannot claim their own approval."

    approval.approver_id = approver_norm
    db.commit()

    log_event(
        db=db,
        stage="CLAIM",
        agent_name="Approval Orchestrator Agent",
        status="INFO",
        details=f"Approval {approval_id} claimed by approver '{approver_norm}'.",
        action_id=approval.action_id,
        approval_id=approval_id,
    )
    return True, f"Approval {approval_id} claimed by '{approver_norm}'."


def approve_action(
    db: Session, approval_id: str, approver_id: str, comment: str = ""
) -> Tuple[bool, str, Optional[str]]:
    """Approves an action and generates the approval token."""
    return approval_orchestrator_agent.process_approval_decision(
        db=db,
        approval_id=approval_id,
        approver_id=approver_id,
        decision="APPROVED",
        comment=comment,
    )


def reject_action(
    db: Session, approval_id: str, approver_id: str, reason: str = ""
) -> Tuple[bool, str]:
    """Rejects an approval request."""
    success, msg, _ = approval_orchestrator_agent.process_approval_decision(
        db=db,
        approval_id=approval_id,
        approver_id=approver_id,
        decision="REJECTED",
        comment=reason,
    )
    return success, msg


def list_pending_approvals(db: Session) -> List[Dict[str, Any]]:
    approvals = (
        db.query(Approval)
        .filter(Approval.status == "PENDING")
        .order_by(Approval.created_at.desc())
        .all()
    )
    results = []
    for app in approvals:
        action = db.query(Action).filter(Action.id == app.action_id).first()
        results.append({
            "id": app.id,
            "approval_id": app.approval_id,
            "action_id": app.action_id,
            "creator_id": app.creator_id,
            "approver_id": app.approver_id,
            "required_role": app.required_role,
            "status": app.status,
            "expires_at": app.expires_at.isoformat(),
            "created_at": app.created_at.isoformat(),
            "action": {
                "action_type": action.action_type if action else "UNKNOWN",
                "amount": action.amount if action else 0.0,
                "currency": action.currency if action else "INR",
                "recipient": action.recipient if action else "UNKNOWN",
                "payload_hash": action.payload_hash if action else "UNKNOWN",
            } if action else None,
        })
    return results
