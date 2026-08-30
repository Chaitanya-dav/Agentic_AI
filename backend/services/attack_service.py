import datetime
from typing import Dict, Any
from sqlalchemy.orm import Session

from backend.models import Action, Approval, Checkpoint, EnvironmentState
from backend.schemas import AttackSimulationResult
from backend.services.action_service import create_action_from_structured
from backend.schemas import ActionCreateStructured
from backend.services.approval_service import approve_action
from backend.services.execution_service import resume_and_execute_action
from backend.services.audit_service import log_event
from backend.security.canonicalization import canonicalize_payload
from backend.security.hashing import calculate_payload_hash


def run_tampering_attack_demo(db: Session) -> AttackSimulationResult:
    """
    ATTACK 1: TAMPERING
    1. Create legitimate action: ₹50,000 -> RAVI (creator=alice)
    2. Legitimate approver Bob approves it -> token issued.
    3. Adversary silently modifies database row: amount changed from 50,000 to 500,000.
    4. Resume triggered.
    5. Deterministic validator re-computes hash and detects approved_hash != current_hash.
    6. Execution REFUSED.
    """
    # 1. Create action
    action = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=50000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Q3 Server Infrastructure Payment",
        ),
    )
    
    approval = db.query(Approval).filter(Approval.action_id == action.id).first()

    # 2. Approve legitimately
    approve_ok, _, token_str = approve_action(db, approval.approval_id, approver_id="bob", comment="Approved ₹50,000 invoice")

    # 3. Tamper with action data directly
    action.amount = 500000.0
    action.description = "Tampered unauthorized ₹500,000 transfer"
    # Note: action.canonical_payload in DB is either unchanged or changed, but live recomputed hash will mismatch token/stored hash!
    db.commit()

    log_event(
        db=db,
        stage="ATTACK_DEMO",
        agent_name="Adversary Simulation",
        status="WARN",
        details=f"[ATTACK 1: TAMPERING] Silently altered Action #{action.id} amount from ₹50,000.00 to ₹500,000.00 in database.",
        action_id=action.id,
        approval_id=approval.approval_id,
    )

    # 4. Resume and attempt execution
    exec_res = resume_and_execute_action(db, action.id, provided_token=token_str)

    return AttackSimulationResult(
        attack_name="Attack 1: Payload Tampering",
        attack_type="TAMPERING",
        description="Adversary altered transaction amount from ₹50,000 to ₹500,000 after human approval was granted.",
        action_id=action.id,
        approval_id=approval.approval_id,
        attempted_state={"tampered_amount": 500000.0, "original_amount": 50000.0, "recipient": "RAVI"},
        security_verification=exec_res.verification_result,
        attack_blocked=(not exec_res.success),
        final_status=action.status,
        explanation="The deterministic security system re-computed the SHA-256 payload hash at resume time. The live hash mismatched both the checkpoint hash and token hash. Execution was safely REFUSED.",
    )


def run_replay_attack_demo(db: Session) -> AttackSimulationResult:
    """
    ATTACK 2: REPLAY ACROSS IDENTICAL APPROVALS
    1. Create Action A: ₹10,000 -> RAVI (approval A001)
    2. Create Action B: ₹10,000 -> RAVI (approval A002)
    Both have the EXACT SAME payload hash.
    3. Action A is approved by Bob -> Token issued for A001.
    4. Action B is NOT yet approved.
    5. Adversary attempts to execute Action B using Action A's approval token!
    6. System checks:
       - payload_hash check: PASS (identical amounts and recipients)
       - approval_id check: FAIL (Token has A001, Action B requires A002)
    7. Execution REFUSED — APPROVAL REPLAY / APPROVAL ID MISMATCH.
    """
    # 1. Create Action A
    action_a = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=10000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Recurring Maintenance",
        ),
    )
    approval_a = db.query(Approval).filter(Approval.action_id == action_a.id).first()
    approve_ok, _, token_a = approve_action(db, approval_a.approval_id, approver_id="bob")

    # 2. Create Action B with identical payload
    action_b = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=10000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Recurring Maintenance",
        ),
    )
    approval_b = db.query(Approval).filter(Approval.action_id == action_b.id).first()

    log_event(
        db=db,
        stage="ATTACK_DEMO",
        agent_name="Adversary Simulation",
        status="WARN",
        details=f"[ATTACK 2: REPLAY] Attempting to execute Action #{action_b.id} (Approval {approval_b.approval_id}) using Approval Token from Action #{action_a.id} ({approval_a.approval_id}).",
        action_id=action_b.id,
        approval_id=approval_b.approval_id,
    )

    # 3. Attempt to resume Action B using Token A
    exec_res = resume_and_execute_action(db, action_b.id, provided_token=token_a)

    return AttackSimulationResult(
        attack_name="Attack 2: Replay Across Identical Approvals",
        attack_type="REPLAY_MISMATCH",
        description="Adversary attempted to execute a new unapproved Action B using an approval token harvested from identical Action A.",
        action_id=action_b.id,
        approval_id=approval_b.approval_id,
        attempted_state={
            "action_a_id": action_a.id,
            "action_a_approval": approval_a.approval_id,
            "action_b_id": action_b.id,
            "action_b_approval": approval_b.approval_id,
            "both_hashes_identical": (action_a.payload_hash == action_b.payload_hash),
        },
        security_verification=exec_res.verification_result,
        attack_blocked=(not exec_res.success),
        final_status=action_b.status,
        explanation="Payload hashes matched perfectly, but the token's approval_id did not match Action B's unique approval_id. Binding BOTH payload_hash and approval_id successfully blocked cross-action replay!",
    )


def run_expiry_attack_demo(db: Session) -> AttackSimulationResult:
    """
    ATTACK 3: EXPIRY
    1. Create action: ₹30,000 -> RAVI
    2. Legitimate approver Bob approves it.
    3. Simulate clock lapse or expired timestamp on approval record.
    4. Resume execution attempted after expiration.
    5. Result: REFUSED — APPROVAL EXPIRED.
    """
    action = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=30000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Expiring Time-Sensitive Authorization",
        ),
    )
    approval = db.query(Approval).filter(Approval.action_id == action.id).first()
    approve_ok, _, token_str = approve_action(db, approval.approval_id, approver_id="bob")

    # Manually expire the approval timestamp
    approval.expires_at = datetime.datetime.utcnow() - datetime.timedelta(hours=2)
    db.commit()

    log_event(
        db=db,
        stage="ATTACK_DEMO",
        agent_name="Adversary Simulation",
        status="WARN",
        details=f"[ATTACK 3: EXPIRY] Set approval {approval.approval_id} expiry to past ({approval.expires_at.isoformat()}) to test TTL check.",
        action_id=action.id,
        approval_id=approval.approval_id,
    )

    exec_res = resume_and_execute_action(db, action.id, provided_token=token_str)

    return AttackSimulationResult(
        attack_name="Attack 3: Expired Approval Execution",
        attack_type="EXPIRY",
        description="Adversary attempted to execute an action after the cryptographic approval TTL window elapsed.",
        action_id=action.id,
        approval_id=approval.approval_id,
        attempted_state={"expires_at": approval.expires_at.isoformat(), "now": datetime.datetime.utcnow().isoformat()},
        security_verification=exec_res.verification_result,
        attack_blocked=(not exec_res.success),
        final_status=action.status,
        explanation="The deterministic time check detected that the current time exceeded the approval's authorized TTL window. Execution was REFUSED.",
    )


def run_self_approval_attack_demo(db: Session) -> AttackSimulationResult:
    """
    ATTACK 4: SELF-APPROVAL (FOUR-EYES VIOLATION)
    1. Creator Alice creates action.
    2. Alice attempts to approve her own action.
    3. Approval Orchestrator refuses token generation and flags Four-Eyes violation.
    """
    action = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=75000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Unauthorized Self-Approved Transfer",
        ),
    )
    approval = db.query(Approval).filter(Approval.action_id == action.id).first()

    # Alice tries to approve her own action
    approve_ok, msg, token_str = approve_action(db, approval.approval_id, approver_id="alice")

    log_event(
        db=db,
        stage="ATTACK_DEMO",
        agent_name="Adversary Simulation",
        status="WARN",
        details=f"[ATTACK 4: SELF-APPROVAL] User 'alice' attempted to approve her own action #{action.id}.",
        action_id=action.id,
        approval_id=approval.approval_id,
    )

    # Attempt resume
    exec_res = resume_and_execute_action(db, action.id, provided_token=token_str)

    return AttackSimulationResult(
        attack_name="Attack 4: Self-Approval (Four-Eyes Violation)",
        attack_type="SELF_APPROVAL",
        description="Initiator 'alice' attempted to self-authorize an action without independent four-eyes managerial oversight.",
        action_id=action.id,
        approval_id=approval.approval_id,
        attempted_state={"creator": "alice", "attempted_approver": "alice"},
        security_verification=exec_res.verification_result,
        attack_blocked=(not exec_res.success),
        final_status=action.status,
        explanation="The Four-Eyes deterministic policy strictly forbids creator_id == approver_id. Approval was denied and execution was REFUSED.",
    )


def run_world_changed_attack_demo(db: Session) -> AttackSimulationResult:
    """
    ADDITIONAL DEMO: WORLD CHANGED / POLICY BOUNDARY DRIFT
    1. Action is created and approved while global risk=LOW and recipient=TRUSTED.
    2. Before execution resumes, global environment shifts: risk=HIGH and recipient=BLOCKED.
    3. Resume triggered.
    4. Deterministic policy validator re-evaluates current environment state and refuses execution!
    """
    # Reset environment to baseline
    env = db.query(EnvironmentState).first()
    if not env:
        env = EnvironmentState(id=1)
        db.add(env)
    env.risk_level = "LOW"
    env.recipient_status = "TRUSTED"
    env.account_status = "ACTIVE"
    env.transaction_limit = 200000.0
    db.commit()

    # 1. Create and approve action
    action = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=45000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Approved under normal market conditions",
        ),
    )
    approval = db.query(Approval).filter(Approval.action_id == action.id).first()
    approve_ok, _, token_str = approve_action(db, approval.approval_id, approver_id="bob")

    # 2. Simulate World Change: Sanctions/AML blocked recipient & elevated risk
    env.risk_level = "HIGH"
    env.recipient_status = "BLOCKED"
    db.commit()

    log_event(
        db=db,
        stage="ATTACK_DEMO",
        agent_name="Environment Drift Simulation",
        status="WARN",
        details=f"[WORLD CHANGED] Altered global environment state to Risk=HIGH, RecipientStatus=BLOCKED prior to Action #{action.id} resume.",
        action_id=action.id,
        approval_id=approval.approval_id,
    )

    # 3. Resume
    exec_res = resume_and_execute_action(db, action.id, provided_token=token_str)

    return AttackSimulationResult(
        attack_name="Demo: World Changed (Boundary Drift)",
        attack_type="POLICY_BOUNDARY_DRIFT",
        description="Approval was cryptographically valid when issued, but real-world policy boundaries changed (Recipient BLOCKED, Risk HIGH) before resume.",
        action_id=action.id,
        approval_id=approval.approval_id,
        attempted_state={"previous_risk": "LOW", "new_risk": "HIGH", "recipient_status": "BLOCKED"},
        security_verification=exec_res.verification_result,
        attack_blocked=(not exec_res.success),
        final_status=action.status,
        explanation="Approval was cryptographically valid, but execution was refused because current policy boundaries changed at resume time.",
    )


def run_normal_transaction_demo(db: Session) -> AttackSimulationResult:
    """
    NORMAL TRANSACTION: COMPLETE SUCCESSFUL WORKFLOW
    1. Create ₹15,000 -> RAVI (creator=alice)
    2. Approver Bob approves -> Token generated.
    3. Resume triggered.
    4. All 9 security checks PASS.
    5. Action EXECUTED, Approval CONSUMED.
    """
    # Reset environment to normal
    env = db.query(EnvironmentState).first()
    if env:
        env.risk_level = "LOW"
        env.recipient_status = "TRUSTED"
        env.account_status = "ACTIVE"
        env.transaction_limit = 200000.0
        db.commit()

    action = create_action_from_structured(
        db,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=15000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Legitimate Vendor Invoice Settlement",
        ),
    )
    approval = db.query(Approval).filter(Approval.action_id == action.id).first()
    approve_ok, _, token_str = approve_action(db, approval.approval_id, approver_id="bob")

    exec_res = resume_and_execute_action(db, action.id, provided_token=token_str)

    return AttackSimulationResult(
        attack_name="Normal Transaction Baseline",
        attack_type="NORMAL_SUCCESS",
        description="Standard legitimate workflow execution through all 4 agents and 9 security checks.",
        action_id=action.id,
        approval_id=approval.approval_id,
        attempted_state={"amount": 15000.0, "creator": "alice", "approver": "bob"},
        security_verification=exec_res.verification_result,
        attack_blocked=False,
        final_status=action.status,
        explanation="All 9 deterministic checks passed cleanly. Action was atomically executed and approval token marked CONSUMED.",
    )
