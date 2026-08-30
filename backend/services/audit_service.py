import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from backend.models import AuditLog


def log_event(
    db: Session,
    stage: str,
    agent_name: str,
    status: str,
    details: str,
    action_id: Optional[int] = None,
    approval_id: Optional[str] = None,
    check_name: Optional[str] = None,
) -> AuditLog:
    """Creates a new persistent audit log entry."""
    entry = AuditLog(
        action_id=action_id,
        approval_id=approval_id,
        stage=stage,
        agent_name=agent_name,
        check_name=check_name,
        status=status.upper(),
        details=details,
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_action_audit_trail(db: Session, action_id: int) -> List[AuditLog]:
    """Retrieves all chronological audit logs associated with an action."""
    return (
        db.query(AuditLog)
        .filter(AuditLog.action_id == action_id)
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        .all()
    )


def get_recent_audit_logs(db: Session, limit: int = 50) -> List[AuditLog]:
    """Retrieves most recent global audit logs."""
    return (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .limit(limit)
        .all()
    )
