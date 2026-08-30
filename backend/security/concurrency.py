"""
Concurrency and Atomic State Transition Management.

In SQLite (used for the prototype), concurrency safety is achieved through:
1. SQLite WAL mode with synchronous=NORMAL and busy timeouts.
2. Atomic SQL conditional updates (Compare-And-Swap / CAS) within a transaction:
   UPDATE approvals SET is_consumed = 1, status = 'CONSUMED' 
   WHERE id = :approval_db_id AND is_consumed = 0;
   
   If the affected rows == 0, another concurrent worker already claimed/consumed the token.

In Production (PostgreSQL), the implementation would use row-level locking:
   SELECT * FROM approvals WHERE id = :approval_db_id FOR UPDATE;
   -- Validate is_consumed == False, then execute and commit.
"""

from typing import Tuple
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.models import Approval, Action


def atomic_consume_approval(db: Session, approval_db_id: int) -> Tuple[bool, str]:
    """
    Atomically transitions an approval to CONSUMED state using CAS (Compare-And-Swap).
    Returns (success, message).
    """
    try:
        # Atomic CAS update
        stmt = text(
            """
            UPDATE approvals 
            SET is_consumed = 1, status = 'CONSUMED' 
            WHERE id = :id AND is_consumed = 0 AND status = 'APPROVED'
            """
        )
        result = db.execute(stmt, {"id": approval_db_id})
        db.commit()

        if result.rowcount == 1:
            return True, "Approval token successfully and atomically consumed for execution."
        else:
            return False, "Concurrent execution conflict: Approval has already been consumed or is not in APPROVED state."
    except Exception as e:
        db.rollback()
        return False, f"Database transaction error during atomic consume: {str(e)}"
