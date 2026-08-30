import uuid
import datetime
from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import Action, Approval, Checkpoint, EnvironmentState
from backend.security.tokens import create_approval_token
from backend.services.audit_service import log_event


class ApprovalOrchestratorAgent:
    """
    2. APPROVAL ORCHESTRATOR AGENT
    - Receives structured action.
    - Determines whether approval is required and assigns approver role.
    - Creates a unique approval_id.
    - Creates approval request and suspends action at a checkpoint.
    - Enforces Four-Eyes Policy: creator_id MUST NOT equal approver_id.
    - Maintains approval state.
    """

    def generate_approval_id(self, action_id: int) -> str:
        date_str = datetime.datetime.utcnow().strftime("%Y%m%d")
        short_id = uuid.uuid4().hex[:6].upper()
        return f"APPR-{date_str}-A{action_id:03d}-{short_id}"

    def evaluate_approval_requirement(self, action_data: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Determines requirement and approver role.
        """
        amount = float(action_data.get("amount", 0.0))
        action_type = action_data.get("action_type", "PAYMENT")
        
        if amount > settings.HIGH_RISK_THRESHOLD or action_type in ("CONFIG_CHANGE", "ACCESS_GRANT"):
            return True, "SECURITY_ADMIN", f"High-risk {action_type} (> ₹{settings.HIGH_RISK_THRESHOLD:,.0f}) requires SECURITY_ADMIN approval."
        else:
            return True, "FINANCE_MANAGER", f"Transaction requires standard FINANCE_MANAGER four-eyes authorization."

    def create_approval_and_checkpoint(
        self,
        db: Session,
        action: Action,
        expires_in_seconds: int = settings.APPROVAL_EXPIRY_SECONDS,
    ) -> Tuple[Approval, Checkpoint]:
        """
        Creates approval request, records suspension checkpoint, and updates action status.
        """
        # 1. Generate unique approval ID
        approval_id = self.generate_approval_id(action.id)
        
        # 2. Determine required role
        _, required_role, reason = self.evaluate_approval_requirement({
            "amount": action.amount,
            "action_type": action.action_type,
        })
        
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in_seconds)

        # 3. Create Approval record
        approval = Approval(
            action_id=action.id,
            approval_id=approval_id,
            creator_id=action.creator.lower().strip(),
            approver_id=None,
            required_role=required_role,
            token=None,
            status="PENDING",
            is_consumed=False,
            expires_at=expires_at,
            created_at=datetime.datetime.utcnow(),
        )
        db.add(approval)
        db.flush()

        # 4. Fetch current environment state for checkpoint snapshot
        env_state = db.query(EnvironmentState).first()
        env_snapshot = {
            "risk_level": env_state.risk_level if env_state else "LOW",
            "recipient_status": env_state.recipient_status if env_state else "TRUSTED",
            "daily_limit": env_state.daily_limit if env_state else 1000000.0,
            "transaction_limit": env_state.transaction_limit if env_state else 200000.0,
            "account_status": env_state.account_status if env_state else "ACTIVE",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        import json
        
        # 5. Create suspension checkpoint
        checkpoint = Checkpoint(
            action_id=action.id,
            approval_id=approval_id,
            canonical_payload=action.canonical_payload,
            payload_hash=action.payload_hash,
            environment_snapshot=json.dumps(env_snapshot),
            created_at=datetime.datetime.utcnow(),
        )
        db.add(checkpoint)

        # 6. Suspend action state
        action.status = "PENDING_APPROVAL"
        db.commit()
        db.refresh(approval)
        db.refresh(checkpoint)

        # 7. Audit log
        log_event(
            db=db,
            stage="ORCHESTRATION",
            agent_name="Approval Orchestrator Agent",
            status="INFO",
            details=f"Created approval {approval_id} for Action #{action.id}. Action suspended and checkpoint saved. Required role: {required_role}.",
            action_id=action.id,
            approval_id=approval_id,
        )

        return approval, checkpoint

    def process_approval_decision(
        self,
        db: Session,
        approval_id: str,
        approver_id: str,
        decision: str,  # "APPROVED" or "REJECTED"
        comment: str = "",
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Processes human approver decision.
        Enforces four-eyes policy (approver_id != creator_id).
        Returns (success, message, token_str_or_none).
        """
        approval = db.query(Approval).filter(Approval.approval_id == approval_id).first()
        if not approval:
            return False, f"Approval ID '{approval_id}' not found.", None

        if approval.status != "PENDING":
            return False, f"Approval is already in '{approval.status}' state.", None

        action = db.query(Action).filter(Action.id == approval.action_id).first()
        if not action:
            return False, f"Associated action #{approval.action_id} not found.", None

        creator_norm = (approval.creator_id or "").strip().lower()
        approver_norm = (approver_id or "").strip().lower()

        # FOUR-EYES ENFORCEMENT
        if creator_norm == approver_norm:
            log_event(
                db=db,
                stage="APPROVAL",
                agent_name="Approval Orchestrator Agent",
                status="FAIL",
                check_name="Four-Eyes Policy Check",
                details=f"Self-Approval Rejected: Approver '{approver_norm}' is identical to Creator '{creator_norm}'.",
                action_id=action.id,
                approval_id=approval.approval_id,
            )
            return False, f"Four-Eyes Policy Violation: Creator '{creator_norm}' cannot approve their own action.", None

        if decision.upper() == "REJECTED":
            approval.status = "REJECTED"
            approval.approver_id = approver_norm
            action.status = "REJECTED"
            db.commit()

            log_event(
                db=db,
                stage="APPROVAL",
                agent_name="Approval Orchestrator Agent",
                status="INFO",
                details=f"Action #{action.id} REJECTED by '{approver_norm}'. Comment: {comment}",
                action_id=action.id,
                approval_id=approval.approval_id,
            )
            return True, f"Approval {approval.approval_id} rejected.", None

        # Issue Cryptographic Approval Token
        token_str = create_approval_token(
            approval_id=approval.approval_id,
            payload_hash=action.payload_hash,
            creator_id=creator_norm,
            approver_id=approver_norm,
            expires_at=approval.expires_at,
        )

        approval.approver_id = approver_norm
        approval.token = token_str
        approval.status = "APPROVED"
        approval.approved_at = datetime.datetime.utcnow()
        action.status = "APPROVED"
        db.commit()

        log_event(
            db=db,
            stage="APPROVAL",
            agent_name="Approval Orchestrator Agent",
            status="PASS",
            details=f"Action #{action.id} APPROVED by '{approver_norm}'. Approval token generated containing payload_hash [{action.payload_hash[:16]}...] and approval_id [{approval.approval_id}].",
            action_id=action.id,
            approval_id=approval.approval_id,
        )

        return True, f"Approval {approval.approval_id} approved successfully.", token_str
