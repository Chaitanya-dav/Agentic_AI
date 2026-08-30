import datetime
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from backend.models import Action, Approval, Checkpoint, EnvironmentState
from backend.schemas import SecurityCheckItem, SecurityVerificationResult
from backend.security.canonicalization import canonicalize_payload
from backend.security.hashing import calculate_payload_hash, verify_hash
from backend.security.tokens import decode_and_verify_token


def evaluate_boundary_conditions(
    action: Action,
    env_state: EnvironmentState,
) -> Tuple[bool, str, List[str]]:
    """
    Evaluates dynamic environment policies and boundary conditions at RESUME time.
    Returns (is_passed, reason, list_of_violations).
    """
    violations = []
    
    # 1. Account Status
    if env_state.account_status.upper() == "FROZEN":
        violations.append("Source account is FROZEN. All outbound transactions suspended.")
    elif env_state.account_status.upper() == "RESTRICTED" and action.amount > 10000.0:
        violations.append("Source account is RESTRICTED: Max allowable transaction is ₹10,000.00.")

    # 2. Recipient Status
    if env_state.recipient_status.upper() == "BLOCKED":
        violations.append(f"Recipient '{action.recipient}' is listed as BLOCKED in the AML/Sanctions registry.")
    elif env_state.recipient_status.upper() == "SUSPICIOUS" and action.amount > 5000.0:
        violations.append(f"Recipient '{action.recipient}' is marked SUSPICIOUS: Limits capped at ₹5,000.00.")

    # 3. Transaction Limits
    if action.amount > env_state.transaction_limit:
        violations.append(
            f"Transaction amount ₹{action.amount:,.2f} exceeds current maximum transaction limit of ₹{env_state.transaction_limit:,.2f}."
        )

    # 4. Daily Limit
    if action.amount > env_state.daily_limit:
        violations.append(
            f"Transaction amount ₹{action.amount:,.2f} exceeds current daily limit threshold of ₹{env_state.daily_limit:,.2f}."
        )

    # 5. Dynamic Risk Level
    if env_state.risk_level.upper() in ("HIGH", "CRITICAL"):
        if action.amount > 20000.0:
            violations.append(
                f"Global system risk level elevated to {env_state.risk_level}. High-value transfers (> ₹20,000.00) suspended."
            )

    if violations:
        return False, "Current policy boundaries changed: " + "; ".join(violations), violations
        
    return True, "All dynamic boundary and environment policies satisfied.", []


def verify_security_protocol(
    db: Session,
    action_id: int,
    provided_token: Optional[str] = None,
    simulated_now: Optional[datetime.datetime] = None,
) -> SecurityVerificationResult:
    """
    DETERMINISTIC SECURITY VERIFICATION ENGINE.
    
    Executes the strict 9-point security protocol.
    Every check must evaluate to PASS deterministically.
    No LLM or agent can override any check.
    """
    now = simulated_now or datetime.datetime.utcnow()
    checks: List[SecurityCheckItem] = []
    
    # 1. Fetch action
    action = db.query(Action).filter(Action.id == action_id).first()
    if not action:
        return SecurityVerificationResult(
            is_valid=False,
            decision="REFUSED",
            summary="Action record not found in database.",
            explanation="Deterministic verification failed: Target action ID does not exist.",
            checks=[],
            recomputed_hash="N/A",
            checkpoint_hash="N/A",
            stored_approval_id="N/A",
        )

    # Recompute current payload hash deterministically
    current_canonical = canonicalize_payload(action)
    current_recomputed_hash = calculate_payload_hash(current_canonical)
    
    # Check 1: Action stored hash vs recomputed hash
    is_ch1_pass = (action.payload_hash == current_recomputed_hash)
    checks.append(SecurityCheckItem(
        code="CHK_PAYLOAD_INTEGRITY",
        name="Current Payload Hash Recomputation",
        status="PASS" if is_ch1_pass else "FAIL",
        expected=current_recomputed_hash,
        actual=action.payload_hash,
        details="Payload re-canonicalized and hashed via deterministic SHA-256 tool."
        if is_ch1_pass else "Current payload data does not match stored action hash (Tampering Detected!)."
    ))

    # Fetch latest checkpoint
    checkpoint = (
        db.query(Checkpoint)
        .filter(Checkpoint.action_id == action.id)
        .order_by(Checkpoint.id.desc())
        .first()
    )
    checkpoint_hash = checkpoint.payload_hash if checkpoint else "MISSING"

    # Check 2: Checkpoint payload hash vs current recomputed hash
    is_ch2_pass = (checkpoint is not None and checkpoint.payload_hash == current_recomputed_hash)
    checks.append(SecurityCheckItem(
        code="CHK_CHECKPOINT_HASH",
        name="Checkpoint Payload Hash Match",
        status="PASS" if is_ch2_pass else "FAIL",
        expected=current_recomputed_hash,
        actual=checkpoint_hash,
        details="Checkpoint captured during suspension matches current live payload."
        if is_ch2_pass else "Checkpoint hash does not match current payload hash (State modified post-checkpoint!)."
    ))

    # Fetch latest approval
    approval = (
        db.query(Approval)
        .filter(Approval.action_id == action.id)
        .order_by(Approval.id.desc())
        .first()
    )

    if not approval:
        checks.append(SecurityCheckItem(
            code="CHK_APPROVAL_EXISTS",
            name="Approval Record Existence",
            status="FAIL",
            expected="APPROVAL_EXISTS",
            actual="NO_APPROVAL_RECORD",
            details="No approval request has been generated for this action."
        ))
        return SecurityVerificationResult(
            is_valid=False,
            decision="REFUSED",
            summary="Approval record missing.",
            explanation="Action cannot execute without an initialized approval workflow.",
            checks=checks,
            recomputed_hash=current_recomputed_hash,
            checkpoint_hash=checkpoint_hash,
            stored_approval_id="N/A",
        )

    stored_approval_id = approval.approval_id
    token_to_check = provided_token or approval.token
    token_data = None
    token_hash = None
    token_approval_id = None

    if token_to_check:
        token_valid, token_data, token_err = decode_and_verify_token(token_to_check)
        if token_valid and token_data:
            token_hash = token_data.get("payload_hash")
            token_approval_id = token_data.get("approval_id")
        else:
            token_hash = "INVALID_SIGNATURE"
            token_approval_id = "INVALID_SIGNATURE"

    # Check 3: Token payload hash == current payload hash
    is_ch3_pass = (token_hash is not None and token_hash == current_recomputed_hash)
    checks.append(SecurityCheckItem(
        code="CHK_TOKEN_PAYLOAD_HASH",
        name="Token Payload Hash Verification",
        status="PASS" if is_ch3_pass else "FAIL",
        expected=current_recomputed_hash,
        actual=token_hash or "MISSING_TOKEN",
        details="Approval token cryptographically binds the identical SHA-256 payload."
        if is_ch3_pass else f"Token payload hash mismatch (Expected: {current_recomputed_hash[:12]}..., Got: {str(token_hash)[:12]}...)."
    ))

    # Check 4: Token approval_id == stored approval_id (REPLAY DEFENSE)
    is_ch4_pass = (token_approval_id is not None and token_approval_id == stored_approval_id)
    checks.append(SecurityCheckItem(
        code="CHK_APPROVAL_ID_BINDING",
        name="Approval ID & Anti-Replay Binding",
        status="PASS" if is_ch4_pass else "FAIL",
        expected=stored_approval_id,
        actual=token_approval_id or "MISSING_TOKEN",
        details="Approval token matches the unique approval_id for this exact action instance."
        if is_ch4_pass else f"Replay or ID mismatch detected! Token contains '{token_approval_id}' but action requires '{stored_approval_id}'."
    ))

    # Check 5: Expiry Validation
    is_ch5_pass = (approval.expires_at > now)
    checks.append(SecurityCheckItem(
        code="CHK_EXPIRY_VALIDATION",
        name="Approval Time-to-Live (TTL) Expiry",
        status="PASS" if is_ch5_pass else "FAIL",
        expected=f"> {now.isoformat()}",
        actual=approval.expires_at.isoformat(),
        details="Approval timestamp is active and within valid time window."
        if is_ch5_pass else f"Approval has EXPIRED (Expired at {approval.expires_at.isoformat()}, Checked at {now.isoformat()})."
    ))

    # Check 6: Four-Eyes Enforcement (creator != approver)
    creator_norm = (approval.creator_id or "").strip().lower()
    approver_norm = (approval.approver_id or "").strip().lower()
    is_ch6_pass = (
        bool(approver_norm)
        and bool(creator_norm)
        and creator_norm != approver_norm
    )
    checks.append(SecurityCheckItem(
        code="CHK_FOUR_EYES_POLICY",
        name="Four-Eyes Separation of Duty",
        status="PASS" if is_ch6_pass else "FAIL",
        expected=f"Approver != '{creator_norm}'",
        actual=f"Creator: '{creator_norm}', Approver: '{approver_norm}'",
        details="Four-eyes policy satisfied: Action created by and approved by distinct entities."
        if is_ch6_pass else f"Four-Eyes Violation: Self-approval forbidden (Creator: '{creator_norm}' == Approver: '{approver_norm}')."
    ))

    # Check 7: Approval Status
    is_ch7_pass = (approval.status == "APPROVED")
    checks.append(SecurityCheckItem(
        code="CHK_APPROVAL_STATUS",
        name="Approval State Machine Status",
        status="PASS" if is_ch7_pass else "FAIL",
        expected="APPROVED",
        actual=approval.status,
        details="Approval record is currently in APPROVED state."
        if is_ch7_pass else f"Invalid approval state: '{approval.status}'. Must be 'APPROVED'."
    ))

    # Check 8: Consumed Status Check
    is_ch8_pass = (not approval.is_consumed)
    checks.append(SecurityCheckItem(
        code="CHK_NOT_CONSUMED",
        name="Single-Use Non-Consumed Check",
        status="PASS" if is_ch8_pass else "FAIL",
        expected="is_consumed == False",
        actual=f"is_consumed == {approval.is_consumed}",
        details="Approval token is fresh and has not been previously executed."
        if is_ch8_pass else "Double-execution blocked: Approval token has ALREADY BEEN CONSUMED."
    ))

    # Check 9: Dynamic Boundary and Environment Policy
    env_state = db.query(EnvironmentState).first()
    if not env_state:
        # Default fallback baseline
        env_state = EnvironmentState(
            risk_level="LOW",
            recipient_status="TRUSTED",
            daily_limit=1000000.0,
            transaction_limit=200000.0,
            account_status="ACTIVE",
        )
        db.add(env_state)
        db.commit()

    is_ch9_pass, boundary_reason, boundary_violations = evaluate_boundary_conditions(action, env_state)
    checks.append(SecurityCheckItem(
        code="CHK_DYNAMIC_POLICY_BOUNDARIES",
        name="Live Policy & Boundary Re-evaluation",
        status="PASS" if is_ch9_pass else "FAIL",
        expected="ACTIVE account, TRUSTED recipient, limits within budget, low system risk",
        actual=f"Risk: {env_state.risk_level}, Recipient: {env_state.recipient_status}, Acct: {env_state.account_status}, TxLimit: ₹{env_state.transaction_limit:,.0f}",
        details=boundary_reason
    ))

    # Aggregate result
    all_passed = all(
        [is_ch1_pass, is_ch2_pass, is_ch3_pass, is_ch4_pass, is_ch5_pass, is_ch6_pass, is_ch7_pass, is_ch8_pass, is_ch9_pass]
    )

    failed_checks = [c.name for c in checks if c.status == "FAIL"]
    
    if all_passed:
        decision = "PASS"
        summary = "All 9 security verification checks passed deterministically."
        explanation = (
            f"Action #{action.id} ({action.action_type} of {action.currency} {action.amount:,.2f} to {action.recipient}) "
            f"has been verified against SHA-256 payload integrity, Checkpoint hash parity, Token approval_id binding ({stored_approval_id}), "
            f"TTL expiry, Four-Eyes separation (Creator: {creator_norm} vs Approver: {approver_norm}), and live policy boundaries."
        )
    else:
        decision = "REFUSED"
        summary = f"Security verification refused. Failed checks: {', '.join(failed_checks)}"
        explanation = (
            f"Deterministic execution refusal: {len(failed_checks)} critical security policy check(s) failed: "
            + "; ".join([f"[{c.name}: {c.details}]" for c in checks if c.status == "FAIL"])
        )

    return SecurityVerificationResult(
        is_valid=all_passed,
        decision=decision,
        summary=summary,
        explanation=explanation,
        checks=checks,
        recomputed_hash=current_recomputed_hash,
        checkpoint_hash=checkpoint_hash,
        token_hash=token_hash,
        stored_approval_id=stored_approval_id,
        token_approval_id=token_approval_id,
    )
