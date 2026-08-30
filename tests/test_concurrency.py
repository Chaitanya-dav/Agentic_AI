import concurrent.futures
import pytest
from backend.models import Action, Approval
from backend.schemas import ActionCreateStructured
from backend.services.action_service import create_action_from_structured
from backend.services.approval_service import approve_action
from backend.services.execution_service import resume_and_execute_action
from tests.conftest import TestingSessionLocal


def test_concurrent_execution_race_condition(db_session):
    """
    Test 8: Two (or more) simultaneous execution requests produce EXACTLY ONE effect.
    The second (and subsequent) attempt is rejected as already consumed.
    """
    # 1. Create and approve action
    action = create_action_from_structured(
        db_session,
        ActionCreateStructured(
            action_type="PAYMENT",
            amount=50000.0,
            currency="INR",
            recipient="RAVI",
            creator="alice",
            description="Concurrent Race Condition Test",
        ),
    )
    approval = db_session.query(Approval).filter(Approval.action_id == action.id).first()
    approve_ok, _, token_str = approve_action(db_session, approval.approval_id, approver_id="bob")
    assert approve_ok is True

    action_id = action.id

    # 2. Worker function for concurrent threads
    def execution_worker(worker_id: int):
        thread_db = TestingSessionLocal()
        try:
            res = resume_and_execute_action(thread_db, action_id=action_id, provided_token=token_str)
            return {
                "worker_id": worker_id,
                "success": res.success,
                "decision": res.verification_result.decision,
                "message": res.message,
            }
        finally:
            thread_db.close()

    # 3. Fire 10 simultaneous execution requests
    num_threads = 10
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(execution_worker, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    # 4. Strict assertion: Exactly 1 succeeded, 9 failed
    successes = [r for r in results if r["success"] is True]
    failures = [r for r in results if r["success"] is False]

    assert len(successes) == 1, f"Expected exactly 1 execution success, got {len(successes)}"
    assert len(failures) == num_threads - 1, f"Expected {num_threads - 1} refusals, got {len(failures)}"

    # 5. Verify database state
    db_session.expire_all()
    final_action = db_session.query(Action).filter(Action.id == action_id).first()
    final_approval = db_session.query(Approval).filter(Approval.action_id == action_id).first()

    assert final_action.status == "EXECUTED"
    assert final_approval.status == "CONSUMED"
    assert final_approval.is_consumed is True
