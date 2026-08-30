import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.models import Action, Approval, Checkpoint
from backend.schemas import ActionCreateNL, ActionCreateStructured
from backend.agents.graph import action_analysis_agent, approval_orchestrator_agent
from backend.security.canonicalization import canonicalize_payload
from backend.security.hashing import calculate_payload_hash
from backend.services.audit_service import log_event


def create_action_from_nl(db: Session, request: ActionCreateNL) -> Action:
    """
    Workflow:
    CREATE ACTION (from NL) -> CANONICALIZE -> HASH -> CREATE APPROVAL -> SUSPEND & SAVE CHECKPOINT
    """
    # 1. Action Analysis Agent processes natural language
    analysis_res = action_analysis_agent.process(
        prompt=request.natural_language_prompt,
        creator=request.creator or "alice",
    )
    
    extracted = analysis_res["structured_action"]
    canonical_str = analysis_res["canonical_payload"]
    hash_str = analysis_res["payload_hash"]

    # 2. Persist Action entity
    action = Action(
        action_type=extracted["action_type"],
        amount=extracted["amount"],
        currency=extracted["currency"],
        recipient=extracted["recipient"],
        creator=extracted["creator"],
        description=extracted["description"],
        canonical_payload=canonical_str,
        payload_hash=hash_str,
        status="PENDING_APPROVAL",
        created_at=datetime.datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    log_event(
        db=db,
        stage="ANALYSIS",
        agent_name="Action Analysis Agent",
        status="INFO",
        details=(
            f"Parsed Natural Language prompt: '{request.natural_language_prompt}'. "
            f"Extracted: {action.action_type} {action.currency} {action.amount:,.2f} -> {action.recipient}. "
            f"Computed canonical payload and SHA-256 hash: {hash_str[:16]}... Risk: {analysis_res['risk_level']}."
        ),
        action_id=action.id,
    )

    # 3. Approval Orchestrator Agent creates approval record & checkpoint
    approval_orchestrator_agent.create_approval_and_checkpoint(db=db, action=action)

    return action


def create_action_from_structured(db: Session, request: ActionCreateStructured) -> Action:
    """
    Creates action directly from structured fields.
    """
    canonical_str = canonicalize_payload(request)
    hash_str = calculate_payload_hash(canonical_str)

    action = Action(
        action_type=request.action_type.upper(),
        amount=float(request.amount),
        currency=request.currency.upper(),
        recipient=request.recipient.upper(),
        creator=request.creator.lower(),
        description=request.description or "",
        canonical_payload=canonical_str,
        payload_hash=hash_str,
        status="PENDING_APPROVAL",
        created_at=datetime.datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    log_event(
        db=db,
        stage="ANALYSIS",
        agent_name="Action Analysis Agent",
        status="INFO",
        details=f"Created structured Action #{action.id}: {action.action_type} {action.currency} {action.amount:,.2f} to {action.recipient}. SHA-256: {hash_str[:16]}...",
        action_id=action.id,
    )

    approval_orchestrator_agent.create_approval_and_checkpoint(db=db, action=action)
    return action


def list_actions(db: Session, skip: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
    actions = db.query(Action).order_by(Action.id.desc()).offset(skip).limit(limit).all()
    results = []
    for a in actions:
        latest_approval = (
            db.query(Approval)
            .filter(Approval.action_id == a.id)
            .order_by(Approval.id.desc())
            .first()
        )
        approval_dict = None
        if latest_approval:
            approval_dict = {
                "id": latest_approval.id,
                "approval_id": latest_approval.approval_id,
                "creator_id": latest_approval.creator_id,
                "approver_id": latest_approval.approver_id,
                "status": latest_approval.status,
                "is_consumed": latest_approval.is_consumed,
                "expires_at": latest_approval.expires_at.isoformat() if latest_approval.expires_at else None,
                "token": latest_approval.token,
            }

        results.append({
            "id": a.id,
            "action_type": a.action_type,
            "amount": a.amount,
            "currency": a.currency,
            "recipient": a.recipient,
            "creator": a.creator,
            "description": a.description,
            "canonical_payload": a.canonical_payload,
            "payload_hash": a.payload_hash,
            "status": a.status,
            "created_at": a.created_at.isoformat(),
            "updated_at": a.updated_at.isoformat(),
            "approval": approval_dict,
        })
    return results


def get_action_details(db: Session, action_id: int) -> Optional[Dict[str, Any]]:
    action = db.query(Action).filter(Action.id == action_id).first()
    if not action:
        return None

    approvals = db.query(Approval).filter(Approval.action_id == action_id).all()
    checkpoints = db.query(Checkpoint).filter(Checkpoint.action_id == action_id).all()

    return {
        "id": action.id,
        "action_type": action.action_type,
        "amount": action.amount,
        "currency": action.currency,
        "recipient": action.recipient,
        "creator": action.creator,
        "description": action.description,
        "canonical_payload": action.canonical_payload,
        "payload_hash": action.payload_hash,
        "status": action.status,
        "created_at": action.created_at.isoformat(),
        "updated_at": action.updated_at.isoformat(),
        "approvals": [
            {
                "id": app.id,
                "approval_id": app.approval_id,
                "creator_id": app.creator_id,
                "approver_id": app.approver_id,
                "status": app.status,
                "is_consumed": app.is_consumed,
                "expires_at": app.expires_at.isoformat(),
                "token": app.token,
            }
            for app in approvals
        ],
        "checkpoints": [
            {
                "id": cp.id,
                "approval_id": cp.approval_id,
                "canonical_payload": cp.canonical_payload,
                "payload_hash": cp.payload_hash,
                "environment_snapshot": cp.environment_snapshot,
                "created_at": cp.created_at.isoformat(),
            }
            for cp in checkpoints
        ],
    }
