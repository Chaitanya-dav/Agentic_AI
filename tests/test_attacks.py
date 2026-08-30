import datetime
import pytest
from backend.models import Action, Approval, Checkpoint, EnvironmentState
from backend.schemas import ActionCreateStructured
from backend.services.action_service import create_action_from_structured
from backend.services.approval_service import approve_action
from backend.services.execution_service import resume_and_execute_action
from backend.services.attack_service import (
    run_tampering_attack_demo,
    run_replay_attack_demo,
    run_expiry_attack_demo,
    run_self_approval_attack_demo,
    run_world_changed_attack_demo,
    run_normal_transaction_demo,
)


def test_attack1_tampered_payload_fails(db_session):
    """
    ATTACK 1: Tampered payload fails.
    Approved: ₹50,000 -> Ravi.
    Modified: ₹500,000 -> Ravi.
    Expected: REFUSED — approved_hash != current_hash.
    """
    action = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=50000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    _, _, token_str = approve_action(db_session, approval.approval_id, approver_id="bob")

    # Modify payload amount in DB
    action.amount = 500000.0
    db_session.commit()

    exec_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    
    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False
    assert exec_res.verification_result.decision == "REFUSED"
    
    # Verify hash mismatch check failed
    chk = next((c for c in exec_res.verification_result.checks if c.code == "CHK_PAYLOAD_INTEGRITY"), None)
    assert chk is not None
    assert chk.status == "FAIL"


def test_attack2_replay_across_identical_approvals_fails(db_session):
    """
    ATTACK 2: Replay across identical approvals fails.
    Two identical actions:
    Action A: ₹10,000 -> Ravi, A001
    Action B: ₹10,000 -> Ravi, A002
    Same payload hash, different approval ID.
    Token A used for Action B.
    Expected:
    payload_hash check = PASS
    approval_id check = FAIL
    Result: REFUSED.
    """
    # Action A
    action_a = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=10000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval_a = db_session.query(Approval).filter(Approval.action_id == action_a.id).first()
    _, _, token_a = approve_action(db_session, approval_a.approval_id, approver_id="bob")

    # Action B
    action_b = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=10000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval_b = db_session.query(Approval).filter(Approval.action_id == action_b.id).first()

    # Confirm payload hashes are identical
    assert action_a.payload_hash == action_b.payload_hash
    assert approval_a.approval_id != approval_b.approval_id

    # Attempt to execute Action B using Token A
    exec_res = resume_and_execute_action(db_session, action_b.id, provided_token=token_a)

    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False
    assert exec_res.verification_result.decision == "REFUSED"

    # Verify payload hash check PASSED, but approval_id check FAILED
    token_hash_chk = next((c for c in exec_res.verification_result.checks if c.code == "CHK_TOKEN_PAYLOAD_HASH"), None)
    assert token_hash_chk is not None
    assert token_hash_chk.status == "PASS"

    approval_id_chk = next((c for c in exec_res.verification_result.checks if c.code == "CHK_APPROVAL_ID_BINDING"), None)
    assert approval_id_chk is not None
    assert approval_id_chk.status == "FAIL"


def test_attack3_expired_approval_fails(db_session):
    """
    ATTACK 3: Expired approval fails.
    Approved action has TTL in past.
    Result: REFUSED — APPROVAL EXPIRED.
    """
    action = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=20000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    _, _, token_str = approve_action(db_session, approval.approval_id, approver_id="bob")

    # Manually expire
    approval.expires_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=100)
    db_session.commit()

    exec_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False
    
    expiry_chk = next((c for c in exec_res.verification_result.checks if c.code == "CHK_EXPIRY_VALIDATION"), None)
    assert expiry_chk is not None
    assert expiry_chk.status == "FAIL"


def test_attack4_self_approval_fails(db_session):
    """
    ATTACK 4: Self-approval fails.
    Creator: Alice. Approver: Alice.
    Result: REFUSED — FOUR-EYES POLICY VIOLATION.
    """
    action = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=50000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()

    # Alice tries to approve
    approve_ok, msg, token = approve_action(db_session, approval.approval_id, approver_id="alice")
    assert approve_ok is False
    assert "Four-Eyes" in msg or "cannot approve" in msg
    assert token is None

    # Resume must be refused
    exec_res = resume_and_execute_action(db_session, action.id)
    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False


def test_attack5_world_changed_boundary_fails(db_session):
    """
    ADDITIONAL DEMO: World Changed / Boundary Drift.
    Approved when risk=LOW, recipient=TRUSTED.
    Later: recipient=BLOCKED or risk=HIGH.
    Result: REFUSED — Current policy boundaries changed.
    """
    env = db_session.query(EnvironmentState).first()
    env.risk_level = "LOW"
    env.recipient_status = "TRUSTED"
    db_session.commit()

    action = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=40000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    _, _, token_str = approve_action(db_session, approval.approval_id, approver_id="bob")

    # Change environment
    env.recipient_status = "BLOCKED"
    db_session.commit()

    exec_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    assert exec_res.success is False
    assert exec_res.verification_result.is_valid is False

    boundary_chk = next((c for c in exec_res.verification_result.checks if c.code == "CHK_DYNAMIC_POLICY_BOUNDARIES"), None)
    assert boundary_chk is not None
    assert boundary_chk.status == "FAIL"


def test_consumed_approval_cannot_execute_again(db_session):
    """
    Test 7: Consumed approval cannot execute again (Double-execution prevention).
    """
    action = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT", amount=12000.0, currency="INR", recipient="RAVI", creator="alice"
        ),
    )
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    _, _, token_str = approve_action(db_session, approval.approval_id, approver_id="bob")

    # First execution succeeds
    first_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    assert first_res.success is True

    # Second execution attempt fails
    second_res = resume_and_execute_action(db_session, action.id, provided_token=token_str)
    assert second_res.success is False
    assert second_res.verification_result.is_valid is False

    consumed_chk = next((c for c in second_res.verification_result.checks if c.code == "CHK_NOT_CONSUMED"), None)
    assert consumed_chk is not None
    assert consumed_chk.status == "FAIL"


def test_attack_lab_service_demos(db_session):
    """
    Test all demo runner functions directly.
    """
    t_res = run_tampering_attack_demo(db_session)
    assert t_res.attack_blocked is True

    r_res = run_replay_attack_demo(db_session)
    assert r_res.attack_blocked is True

    e_res = run_expiry_attack_demo(db_session)
    assert e_res.attack_blocked is True

    s_res = run_self_approval_attack_demo(db_session)
    assert s_res.attack_blocked is True

    w_res = run_world_changed_attack_demo(db_session)
    assert w_res.attack_blocked is True

    n_res = run_normal_transaction_demo(db_session)
    assert n_res.attack_blocked is False
    assert n_res.final_status == "EXECUTED"


def test_api_attack_endpoints(client):
    """
    Test FastAPI endpoints for attack demonstrations.
    """
    resp = client.post("/attacks/tamper")
    assert resp.status_code == 200
    data = resp.json()
    assert data["attack_blocked"] is True

    resp = client.post("/attacks/replay")
    assert resp.status_code == 200
    assert resp.json()["attack_blocked"] is True

    resp = client.post("/attacks/expiry")
    assert resp.status_code == 200
    assert resp.json()["attack_blocked"] is True

    resp = client.post("/attacks/self-approval")
    assert resp.status_code == 200
    assert resp.json()["attack_blocked"] is True

    resp = client.post("/attacks/world-changed")
    assert resp.status_code == 200
    assert resp.json()["attack_blocked"] is True

    resp = client.post("/attacks/normal")
    assert resp.status_code == 200
    assert resp.json()["attack_blocked"] is False
