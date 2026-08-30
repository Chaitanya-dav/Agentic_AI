import os
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import engine, Base, get_db
from backend.models import Action, Approval, Checkpoint, AuditLog, EnvironmentState, User
from backend.schemas import (
    ActionCreateNL,
    ActionCreateStructured,
    ActionResponse,
    ApprovalClaimRequest,
    ApprovalDecisionRequest,
    ApprovalRejectRequest,
    ApprovalResponse,
    SecurityVerificationResult,
    ExecutionResult,
    AttackSimulationResult,
    AuditLogResponse,
    EnvironmentStateUpdate,
    EnvironmentStateResponse,
    DashboardMetrics,
)
from backend.services.action_service import (
    create_action_from_nl,
    create_action_from_structured,
    list_actions,
    get_action_details,
)
from backend.services.approval_service import (
    claim_approval,
    approve_action,
    reject_action,
    list_pending_approvals,
)
from backend.services.execution_service import (
    resume_and_execute_action,
    verify_action_security_only,
)
from backend.services.attack_service import (
    run_tampering_attack_demo,
    run_replay_attack_demo,
    run_expiry_attack_demo,
    run_self_approval_attack_demo,
    run_world_changed_attack_demo,
    run_normal_transaction_demo,
)
from backend.services.audit_service import (
    get_action_audit_trail,
    get_recent_audit_logs,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB Tables on startup
    Base.metadata.create_all(bind=engine)
    
    # Seed initial environment state and demo users if empty
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        env = db.query(EnvironmentState).first()
        if not env:
            env = EnvironmentState(
                id=1,
                risk_level="LOW",
                recipient_status="TRUSTED",
                daily_limit=1000000.0,
                transaction_limit=200000.0,
                account_status="ACTIVE",
            )
            db.add(env)
            db.commit()

        if db.query(User).count() == 0:
            db.add_all([
                User(username="alice", role="OPERATOR"),
                User(username="bob", role="MANAGER"),
                User(username="carol", role="SECURITY_ADMIN"),
            ])
            db.commit()
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Agentic AI-Driven Secure Approval and Execution System with Deterministic Cryptographic Security Protocol",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- HEALTH & METRICS ---

@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "mock_llm_mode": settings.USE_MOCK_LLM,
        "has_openai_key": bool(settings.OPENAI_API_KEY),
    }


@app.get("/metrics", response_model=DashboardMetrics, tags=["Metrics"])
@app.get("/api/metrics", response_model=DashboardMetrics, tags=["Metrics"])
def get_metrics(db: Session = Depends(get_db)):
    total = db.query(Action).count()
    pending = db.query(Action).filter(Action.status == "PENDING_APPROVAL").count()
    approved = db.query(Action).filter(Action.status == "APPROVED").count()
    executed = db.query(Action).filter(Action.status == "EXECUTED").count()
    refused = db.query(Action).filter(Action.status == "REFUSED").count()
    
    # Attack blocks are failed checks in attack_demo or execution stages
    attacks_blocked = (
        db.query(AuditLog)
        .filter(AuditLog.status == "FAIL")
        .count()
    )
    
    return DashboardMetrics(
        total_actions=total,
        pending_approvals=pending,
        approved_actions=approved,
        executed_actions=executed,
        refused_actions=refused,
        attacks_blocked=attacks_blocked,
    )


# --- ACTIONS ENDPOINTS ---

@app.post("/actions", tags=["Actions"])
@app.post("/api/actions", tags=["Actions"])
def create_action(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
):
    """
    Creates an action.
    Accepts either natural language prompt: {"natural_language_prompt": "...", "creator": "alice"}
    or structured fields: {"action_type": "...", "amount": 50000, "recipient": "RAVI", ...}
    """
    if "natural_language_prompt" in payload:
        req = ActionCreateNL(**payload)
        action = create_action_from_nl(db, req)
    else:
        req = ActionCreateStructured(**payload)
        action = create_action_from_structured(db, req)

    details = get_action_details(db, action.id)
    return details


@app.get("/actions", tags=["Actions"])
@app.get("/api/actions", tags=["Actions"])
def get_actions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return list_actions(db, skip=skip, limit=limit)


@app.get("/actions/{action_id}", tags=["Actions"])
@app.get("/api/actions/{action_id}", tags=["Actions"])
def get_action(action_id: int, db: Session = Depends(get_db)):
    details = get_action_details(db, action_id)
    if not details:
        raise HTTPException(status_code=404, detail="Action not found")
    return details


# --- APPROVALS ENDPOINTS ---

@app.get("/approvals/pending", tags=["Approvals"])
@app.get("/api/approvals/pending", tags=["Approvals"])
def get_pending_approvals(db: Session = Depends(get_db)):
    return list_pending_approvals(db)


@app.post("/approvals/{approval_id}/claim", tags=["Approvals"])
@app.post("/api/approvals/{approval_id}/claim", tags=["Approvals"])
def claim_approval_endpoint(
    approval_id: str,
    req: ApprovalClaimRequest,
    db: Session = Depends(get_db),
):
    success, msg = claim_approval(db, approval_id, req.approver_id)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}


@app.post("/approvals/{approval_id}/approve", tags=["Approvals"])
@app.post("/api/approvals/{approval_id}/approve", tags=["Approvals"])
def approve_action_endpoint(
    approval_id: str,
    req: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
):
    success, msg, token = approve_action(db, approval_id, req.approver_id, req.comment or "")
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg, "token": token}


@app.post("/approvals/{approval_id}/reject", tags=["Approvals"])
@app.post("/api/approvals/{approval_id}/reject", tags=["Approvals"])
def reject_action_endpoint(
    approval_id: str,
    req: ApprovalRejectRequest,
    db: Session = Depends(get_db),
):
    success, msg = reject_action(db, approval_id, req.approver_id, req.reason)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}


# --- RESUME & EXECUTE ENDPOINTS ---

@app.post("/actions/{action_id}/resume", response_model=ExecutionResult, tags=["Execution"])
@app.post("/api/actions/{action_id}/resume", response_model=ExecutionResult, tags=["Execution"])
def resume_action(
    action_id: int,
    payload: Optional[Dict[str, Any]] = Body(default=None),
    db: Session = Depends(get_db),
):
    token = payload.get("token") if payload else None
    return resume_and_execute_action(db, action_id=action_id, provided_token=token)


@app.post("/actions/{action_id}/execute", response_model=ExecutionResult, tags=["Execution"])
@app.post("/api/actions/{action_id}/execute", response_model=ExecutionResult, tags=["Execution"])
def execute_action_endpoint(
    action_id: int,
    payload: Optional[Dict[str, Any]] = Body(default=None),
    db: Session = Depends(get_db),
):
    token = payload.get("token") if payload else None
    return resume_and_execute_action(db, action_id=action_id, provided_token=token)


@app.post("/actions/{action_id}/verify", response_model=SecurityVerificationResult, tags=["Execution"])
@app.post("/api/actions/{action_id}/verify", response_model=SecurityVerificationResult, tags=["Execution"])
def verify_action_endpoint(
    action_id: int,
    payload: Optional[Dict[str, Any]] = Body(default=None),
    db: Session = Depends(get_db),
):
    token = payload.get("token") if payload else None
    return verify_action_security_only(db, action_id=action_id, provided_token=token)


# --- ATTACK DEMONSTRATIONS LAB ---

@app.post("/attacks/tamper", response_model=AttackSimulationResult, tags=["Attack Lab"])
@app.post("/api/attacks/tamper", response_model=AttackSimulationResult, tags=["Attack Lab"])
def attack_tamper(db: Session = Depends(get_db)):
    """ATTACK 1: Payload tampering demonstration."""
    return run_tampering_attack_demo(db)


@app.post("/attacks/replay", response_model=AttackSimulationResult, tags=["Attack Lab"])
@app.post("/api/attacks/replay", response_model=AttackSimulationResult, tags=["Attack Lab"])
def attack_replay(db: Session = Depends(get_db)):
    """ATTACK 2: Replay across identical approvals demonstration."""
    return run_replay_attack_demo(db)


@app.post("/attacks/expiry", response_model=AttackSimulationResult, tags=["Attack Lab"])
@app.post("/api/attacks/expiry", response_model=AttackSimulationResult, tags=["Attack Lab"])
def attack_expiry(db: Session = Depends(get_db)):
    """ATTACK 3: Expired approval execution demonstration."""
    return run_expiry_attack_demo(db)


@app.post("/attacks/self-approval", response_model=AttackSimulationResult, tags=["Attack Lab"])
@app.post("/api/attacks/self-approval", response_model=AttackSimulationResult, tags=["Attack Lab"])
def attack_self_approval(db: Session = Depends(get_db)):
    """ATTACK 4: Self-approval / Four-eyes violation demonstration."""
    return run_self_approval_attack_demo(db)


@app.post("/attacks/world-changed", response_model=AttackSimulationResult, tags=["Attack Lab"])
@app.post("/api/attacks/world-changed", response_model=AttackSimulationResult, tags=["Attack Lab"])
def attack_world_changed(db: Session = Depends(get_db)):
    """ADDITIONAL DEMO: World changed / Policy boundary drift demonstration."""
    return run_world_changed_attack_demo(db)


@app.post("/attacks/normal", response_model=AttackSimulationResult, tags=["Attack Lab"])
@app.post("/api/attacks/normal", response_model=AttackSimulationResult, tags=["Attack Lab"])
def normal_transaction_demo(db: Session = Depends(get_db)):
    """NORMAL TRANSACTION: Full legitimate workflow demonstration."""
    return run_normal_transaction_demo(db)


# --- AUDIT TRAIL ENDPOINTS ---

@app.get("/audit/{action_id}", response_model=List[AuditLogResponse], tags=["Audit"])
@app.get("/api/audit/{action_id}", response_model=List[AuditLogResponse], tags=["Audit"])
def get_audit_trail(action_id: int, db: Session = Depends(get_db)):
    return get_action_audit_trail(db, action_id)


@app.get("/audit", response_model=List[AuditLogResponse], tags=["Audit"])
@app.get("/api/audit", response_model=List[AuditLogResponse], tags=["Audit"])
def get_recent_audits(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    return get_recent_audit_logs(db, limit=limit)


# --- ENVIRONMENT STATE CONTROLLER ---

@app.get("/environment", response_model=EnvironmentStateResponse, tags=["Environment"])
@app.get("/api/environment", response_model=EnvironmentStateResponse, tags=["Environment"])
def get_environment_state(db: Session = Depends(get_db)):
    env = db.query(EnvironmentState).first()
    if not env:
        env = EnvironmentState(id=1)
        db.add(env)
        db.commit()
        db.refresh(env)
    return env


@app.post("/environment", response_model=EnvironmentStateResponse, tags=["Environment"])
@app.post("/api/environment", response_model=EnvironmentStateResponse, tags=["Environment"])
def update_environment_state(
    update_data: EnvironmentStateUpdate,
    db: Session = Depends(get_db),
):
    env = db.query(EnvironmentState).first()
    if not env:
        env = EnvironmentState(id=1)
        db.add(env)
    
    if update_data.risk_level is not None:
        env.risk_level = update_data.risk_level.upper()
    if update_data.recipient_status is not None:
        env.recipient_status = update_data.recipient_status.upper()
    if update_data.daily_limit is not None:
        env.daily_limit = update_data.daily_limit
    if update_data.transaction_limit is not None:
        env.transaction_limit = update_data.transaction_limit
    if update_data.account_status is not None:
        env.account_status = update_data.account_status.upper()

    db.commit()
    db.refresh(env)
    return env


@app.post("/environment/reset", response_model=EnvironmentStateResponse, tags=["Environment"])
@app.post("/api/environment/reset", response_model=EnvironmentStateResponse, tags=["Environment"])
def reset_environment_state(db: Session = Depends(get_db)):
    env = db.query(EnvironmentState).first()
    if not env:
        env = EnvironmentState(id=1)
        db.add(env)
    
    env.risk_level = "LOW"
    env.recipient_status = "TRUSTED"
    env.daily_limit = 1000000.0
    env.transaction_limit = 200000.0
    env.account_status = "ACTIVE"
    db.commit()
    db.refresh(env)
    return env


# Mount frontend static directory if exists
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_root():
        index_path = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Frontend not found"}
