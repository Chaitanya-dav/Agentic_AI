import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# Action Schemas
class ActionCreateNL(BaseModel):
    natural_language_prompt: str = Field(
        ...,
        description="Natural language request, e.g., 'Transfer ₹50,000 to Ravi for Q3 cloud invoice'",
        json_schema_extra={"example": "Transfer ₹50,000 to Ravi for cloud invoice"},
    )
    creator: Optional[str] = Field("alice", description="Username of initiator")


class ActionCreateStructured(BaseModel):
    action_type: str = Field("PAYMENT", json_schema_extra={"example": "PAYMENT"})
    amount: float = Field(..., gt=0, json_schema_extra={"example": 50000.0})
    currency: str = Field("INR", json_schema_extra={"example": "INR"})
    recipient: str = Field(..., json_schema_extra={"example": "RAVI"})
    creator: str = Field("alice", json_schema_extra={"example": "alice"})
    description: Optional[str] = Field("", json_schema_extra={"example": "Vendor invoice settlement"})


class ActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_type: str
    amount: float
    currency: str
    recipient: str
    creator: str
    description: Optional[str] = None
    canonical_payload: str
    payload_hash: str
    status: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    
    # Active approval summary if present
    approval: Optional[Dict[str, Any]] = None


# Approval Schemas
class ApprovalClaimRequest(BaseModel):
    approver_id: str = Field(..., json_schema_extra={"example": "bob"})


class ApprovalDecisionRequest(BaseModel):
    approver_id: str = Field(..., json_schema_extra={"example": "bob"})
    comment: Optional[str] = Field("Approved via security workflow", json_schema_extra={"example": "Approved"})


class ApprovalRejectRequest(BaseModel):
    approver_id: str = Field(..., json_schema_extra={"example": "bob"})
    reason: str = Field("Risk policy threshold exceeded", json_schema_extra={"example": "Rejected"})


class ApprovalTokenPayload(BaseModel):
    approval_id: str
    payload_hash: str
    creator_id: str
    approver_id: str
    expires_at: str
    signature: str


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_id: int
    approval_id: str
    creator_id: str
    approver_id: Optional[str] = None
    required_role: str
    token: Optional[str] = None
    status: str
    is_consumed: bool
    expires_at: datetime.datetime
    created_at: datetime.datetime
    approved_at: Optional[datetime.datetime] = None


# Security Verification Check Model
class SecurityCheckItem(BaseModel):
    code: str
    name: str
    status: str  # PASS, FAIL
    expected: str
    actual: str
    details: str


class SecurityVerificationResult(BaseModel):
    is_valid: bool
    decision: str  # PASS, REFUSED
    summary: str
    explanation: str
    checks: List[SecurityCheckItem]
    recomputed_hash: str
    checkpoint_hash: str
    token_hash: Optional[str] = None
    stored_approval_id: str
    token_approval_id: Optional[str] = None


# Execution Result
class ExecutionResult(BaseModel):
    success: bool
    message: str
    action_id: int
    approval_id: str
    verification_result: SecurityVerificationResult
    executed_at: Optional[datetime.datetime] = None


# Attack Simulation Result
class AttackSimulationResult(BaseModel):
    attack_name: str
    attack_type: str
    description: str
    action_id: int
    approval_id: str
    attempted_state: Dict[str, Any]
    security_verification: SecurityVerificationResult
    attack_blocked: bool
    final_status: str
    explanation: str


# Audit Log Schemas
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_id: Optional[int] = None
    approval_id: Optional[str] = None
    stage: str
    agent_name: str
    check_name: Optional[str] = None
    status: str
    details: str
    timestamp: datetime.datetime


# Environment State Schemas
class EnvironmentStateUpdate(BaseModel):
    risk_level: Optional[str] = Field(None, json_schema_extra={"example": "LOW"})
    recipient_status: Optional[str] = Field(None, json_schema_extra={"example": "TRUSTED"})
    daily_limit: Optional[float] = Field(None, json_schema_extra={"example": 1000000.0})
    transaction_limit: Optional[float] = Field(None, json_schema_extra={"example": 200000.0})
    account_status: Optional[str] = Field(None, json_schema_extra={"example": "ACTIVE"})


class EnvironmentStateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    risk_level: str
    recipient_status: str
    daily_limit: float
    transaction_limit: float
    account_status: str
    updated_at: datetime.datetime


# Dashboard Metrics Schema
class DashboardMetrics(BaseModel):
    total_actions: int
    pending_approvals: int
    approved_actions: int
    executed_actions: int
    refused_actions: int
    attacks_blocked: int
