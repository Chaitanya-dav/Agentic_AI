import pytest
from backend.models import Action, Approval, Checkpoint, AuditLog
from backend.services.action_service import create_action_from_nl, create_action_from_structured
from backend.schemas import ActionCreateNL, ActionCreateStructured
from backend.services.approval_service import claim_approval, approve_action, reject_action
from backend.services.execution_service import resume_and_execute_action, verify_action_security_only


def test_normal_approval_workflow_success(db_session):
    """
    Test 1: Full legitimate end-to-end lifecycle.
    Create NL -> Parse & Canonicalize -> Hash -> Suspend/Checkpoint -> Approve (Bob) -> Resume -> Execute.
    """
    # 1. Create action from Natural Language
    req = ActionCreateNL(
        natural_language_prompt="Transfer ₹50,000 to Ravi for cloud server infrastructure",
        creator="alice",
    )
    action = create_action_from_nl(db_session, req)
    
    assert action.id is not None
    assert action.status == "PENDING_APPROVAL"
    assert action.amount == 50000.0
    assert action.recipient == "RAVI"
    assert action.creator == "alice"
    assert len(action.payload_hash) == 64
    assert "=" in action.canonical_payload

    # 2. Check suspension checkpoint
    checkpoint = db_session.query(Checkpoint).filter(Checkpoint.action_id == action.id).first()
    assert checkpoint is not None
    assert checkpoint.payload_hash == action.payload_hash

    # 3. Check approval record
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    assert approval is not None
    assert approval.status == "PENDING"
    assert approval.is_consumed is False
    assert approval.approval_id.startswith("APPR-")

    # 4. Approver Bob claims and approves
    claim_ok, claim_msg = claim_approval(db_session, approval.approval_id, approver_id="bob")
    assert claim_ok is True

    approve_ok, approve_msg, token_str = approve_action(
        db_session, approval.approval_id, approver_id="bob", comment="Legitimate IT expense"
    )
    assert approve_ok is True
    assert token_str is not None
    assert approval.status == "APPROVED"
    assert action.status == "APPROVED"

    # 5. Resume and execute
    exec_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    
    assert exec_res.success is True
    assert exec_res.verification_result.is_valid is True
    assert exec_res.verification_result.decision == "PASS"
    assert all(chk.status == "PASS" for chk in exec_res.verification_result.checks)

    # 6. Verify final state and atomic consumed status
    db_session.refresh(action)
    db_session.refresh(approval)
    assert action.status == "EXECUTED"
    assert approval.status == "CONSUMED"
    assert approval.is_consumed is True

    # 7. Check audit logs
    audits = db_session.query(AuditLog).filter(AuditLog.action_id == action.id).all()
    stages = [a.stage for a in audits]
    assert "ANALYSIS" in stages
    assert "ORCHESTRATION" in stages
    assert "APPROVAL" in stages
    assert "RESUME" in stages
    assert "SECURITY_CHECK" in stages
    assert "EXECUTION" in stages


def test_structured_creation_and_rejection(db_session):
    """
    Test rejection workflow.
    """
    req = ActionCreateStructured(
        action_type="PAYMENT",
        amount=15000.0,
        currency="INR",
        recipient="VENDOR_XYZ",
        creator="alice",
        description="Dubious vendor request",
    )
    action = create_action_from_structured(db_session, req)
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()

    reject_ok, msg = reject_action(
        db_session, approval.approval_id, approver_id="bob", reason="Vendor not verified"
    )
    assert reject_ok is True
    
    db_session.refresh(action)
    db_session.refresh(approval)
    assert approval.status == "REJECTED"
    assert action.status == "REJECTED"

    # Resuming rejected action must fail
    res = resume_and_execute_action(db_session, action.id)
    assert res.success is False
    assert res.verification_result.is_valid is False
    assert res.verification_result.decision == "REFUSED"


def test_checkpoint_hash_mismatch_fails(db_session):
    """
    Test that if checkpoint hash is corrupted/mismatched, security verification REFUSES.
    """
    req = ActionCreateStructured(
        action_type="PAYMENT",
        amount=25000.0,
        currency="INR",
        recipient="RAVI",
        creator="alice",
        description="Audit test",
    )
    action = create_action_from_structured(db_session, req)
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    approve_ok, _, token_str = approve_action(db_session, approval.approval_id, approver_id="bob")

    # Corrupt the checkpoint hash
    checkpoint = db_session.query(Checkpoint).filter(Checkpoint.action_id == action.id).first()
    checkpoint.payload_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    db_session.commit()

    # Resume must detect checkpoint mismatch
    exec_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False
    
    # Check that CHK_CHECKPOINT_HASH failed
    chk_res = next((c for c in exec_res.verification_result.checks if c.code == "CHK_CHECKPOINT_HASH"), None)
    assert chk_res is not None
    assert chk_res.status == "FAIL"


def test_approval_id_mismatch_with_matching_payload_hash(db_session):
    """
    Test that even if payload hashes match, approval_id mismatch strictly fails.
    """
    # Action 1
    a1 = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=5000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    app1 = db_session.query(Approval).filter(Approval.action_id == a1.id).first()
    _, _, token1 = approve_action(db_session, app1.approval_id, approver_id="bob")

    # Action 2 with identical payload
    a2 = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=5000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    app2 = db_session.query(Approval).filter(Approval.action_id == a2.id).first()
    _, _, token2 = approve_action(db_session, app2.approval_id, approver_id="bob")

    assert a1.payload_hash == a2.payload_hash
    assert app1.approval_id != app2.approval_id

    # Attempt to execute Action 2 using Token 1 (mismatched approval_id)
    exec_res = resume_and_execute_action(db_session, a2.id, provided_token=token1)
    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False
    
    id_chk = next((c for c in exec_res.verification_result.checks if c.code == "CHK_APPROVAL_ID_BINDING"), None)
    assert id_chk is not None
    assert id_chk.status == "FAIL"
