import datetime
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from backend.models import Action, Approval
from backend.schemas import ExecutionResult, SecurityVerificationResult
from backend.security.concurrency import atomic_consume_approval
from backend.services.audit_service import log_event


class ExecutionAgent:
    """
    4. EXECUTION AGENT
    - Executes an action ONLY when the security verification result is valid.
    - Uses a database transaction.
    - Ensures exactly-once execution.
    - Marks the approval as CONSUMED.
    - Record the execution in audit logs.
    - If verification fails, do not execute.
    """

    def execute(
        self,
        db: Session,
        action_id: int,
        verification_result: SecurityVerificationResult,
    ) -> ExecutionResult:
        action = db.query(Action).filter(Action.id == action_id).first()
        if not action:
            return ExecutionResult(
                success=False,
                message=f"Action #{action_id} not found.",
                action_id=action_id,
                approval_id=verification_result.stored_approval_id,
                verification_result=verification_result,
            )

        approval = (
            db.query(Approval)
            .filter(Approval.action_id == action_id)
            .order_by(Approval.id.desc())
            .first()
        )

        approval_id_str = approval.approval_id if approval else verification_result.stored_approval_id

        # 1. If action is already executed, reject without overwriting status
        if action.status == "EXECUTED":
            log_event(
                db=db,
                stage="EXECUTION",
                agent_name="Execution Agent",
                status="FAIL",
                check_name="Idempotency Gate",
                details=f"Duplicate execution blocked: Action #{action.id} is already in EXECUTED state.",
                action_id=action.id,
                approval_id=approval_id_str,
            )
            return ExecutionResult(
                success=False,
                message="Duplicate execution blocked: Action has already been executed.",
                action_id=action.id,
                approval_id=approval_id_str,
                verification_result=verification_result,
            )

        # 2. Check if security verification passed
        if not verification_result.is_valid:
            if action.status != "EXECUTED":
                action.status = "REFUSED"
                db.commit()

            log_event(
                db=db,
                stage="EXECUTION",
                agent_name="Execution Agent",
                status="FAIL",
                check_name="Pre-Execution Gate",
                details=f"Execution REFUSED for Action #{action.id}: Security verification failed. {verification_result.summary}",
                action_id=action.id,
                approval_id=approval_id_str,
            )

            return ExecutionResult(
                success=False,
                message=f"Execution Refused: {verification_result.summary}",
                action_id=action.id,
                approval_id=approval_id_str,
                verification_result=verification_result,
            )

        if not approval:
            return ExecutionResult(
                success=False,
                message="No associated approval record found.",
                action_id=action.id,
                approval_id=approval_id_str,
                verification_result=verification_result,
            )

        # 3. Atomic CAS Consume to prevent race conditions / duplicate executions
        consumed_ok, cas_msg = atomic_consume_approval(db, approval.id)
        if not consumed_ok:
            if action.status != "EXECUTED":
                action.status = "REFUSED"
                db.commit()

            log_event(
                db=db,
                stage="EXECUTION",
                agent_name="Execution Agent",
                status="FAIL",
                check_name="Concurrency Check",
                details=f"Execution Refused: {cas_msg}",
                action_id=action.id,
                approval_id=approval_id_str,
            )

            return ExecutionResult(
                success=False,
                message=f"Execution Aborted: {cas_msg}",
                action_id=action.id,
                approval_id=approval_id_str,
                verification_result=verification_result,
            )

        # 3. Simulate successful payload execution (e.g. core banking API / ledger settlement)
        action.status = "EXECUTED"
        db.commit()

        exec_time = datetime.datetime.utcnow()
        log_event(
            db=db,
            stage="EXECUTION",
            agent_name="Execution Agent",
            status="PASS",
            check_name="Payload Settlement",
            details=(
                f"Action #{action.id} successfully EXECUTED at {exec_time.isoformat()}! "
                f"Settled {action.currency} {action.amount:,.2f} to {action.recipient}. "
                f"Approval {approval.approval_id} transitioned to state CONSUMED."
            ),
            action_id=action.id,
            approval_id=approval.approval_id,
        )

        return ExecutionResult(
            success=True,
            message=f"Transaction successfully executed and settled. {action.currency} {action.amount:,.2f} transferred to {action.recipient}.",
            action_id=action.id,
            approval_id=approval.approval_id,
            verification_result=verification_result,
            executed_at=exec_time,
        )
