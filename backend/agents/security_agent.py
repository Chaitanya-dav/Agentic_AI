import datetime
from typing import Optional
from sqlalchemy.orm import Session

from backend.schemas import SecurityVerificationResult
from backend.security.policy import verify_security_protocol
from backend.services.audit_service import log_event


class SecurityVerificationAgent:
    """
    3. SECURITY VERIFICATION AGENT
    - Verifies an action before execution.
    - Calls deterministic security tools to check:
      1. current payload hash
      2. checkpoint payload hash
      3. token payload hash
      4. approval_id
      5. expiry
      6. creator/approver separation
      7. approval status
      8. whether approval has already been consumed
      9. current policy/boundary conditions
    - Produces a human-readable explanation of the decision.
    - The agent investigates and explains, but deterministic security functions make the actual PASS/REFUSE decision.
    """

    def verify(
        self,
        db: Session,
        action_id: int,
        provided_token: Optional[str] = None,
        simulated_now: Optional[datetime.datetime] = None,
    ) -> SecurityVerificationResult:
        # Invoke deterministic security protocol validator
        result = verify_security_protocol(
            db=db,
            action_id=action_id,
            provided_token=provided_token,
            simulated_now=simulated_now,
        )

        # Audit log the verification evaluation
        for chk in result.checks:
            log_event(
                db=db,
                stage="SECURITY_CHECK",
                agent_name="Security Verification Agent",
                status=chk.status,
                check_name=chk.name,
                details=f"[{chk.code}] Expected: {chk.expected} | Actual: {chk.actual} -> {chk.details}",
                action_id=action_id,
                approval_id=result.stored_approval_id,
            )

        log_event(
            db=db,
            stage="SECURITY_CHECK",
            agent_name="Security Verification Agent",
            status="PASS" if result.is_valid else "FAIL",
            check_name="Aggregate Decision",
            details=f"Decision: {result.decision}. Summary: {result.summary}",
            action_id=action_id,
            approval_id=result.stored_approval_id,
        )

        return result
