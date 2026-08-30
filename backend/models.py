import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from backend.database import Base


class Action(Base):
    __tablename__ = "actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action_type = Column(String(64), nullable=False, default="PAYMENT")
    amount = Column(Float, nullable=False, default=0.0)
    currency = Column(String(16), nullable=False, default="INR")
    recipient = Column(String(128), nullable=False)
    creator = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    
    canonical_payload = Column(Text, nullable=False)
    payload_hash = Column(String(64), nullable=False, index=True)
    
    # Status: PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED, REFUSED
    status = Column(String(32), nullable=False, default="PENDING_APPROVAL", index=True)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    # Relationships
    approvals = relationship("Approval", back_populates="action", cascade="all, delete-orphan")
    checkpoints = relationship("Checkpoint", back_populates="action", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="action", cascade="all, delete-orphan")


class Approval(Base):
    __tablename__ = "approvals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action_id = Column(Integer, ForeignKey("actions.id", ondelete="CASCADE"), nullable=False, index=True)
    approval_id = Column(String(64), unique=True, nullable=False, index=True)
    
    creator_id = Column(String(128), nullable=False)
    approver_id = Column(String(128), nullable=True)
    required_role = Column(String(64), nullable=False, default="MANAGER")
    
    token = Column(Text, nullable=True)  # Structured JSON / HMAC signed token string
    
    # Status: PENDING, APPROVED, REJECTED, EXPIRED, CONSUMED
    status = Column(String(32), nullable=False, default="PENDING", index=True)
    is_consumed = Column(Boolean, default=False, nullable=False, index=True)
    
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    approved_at = Column(DateTime, nullable=True)

    # Relationships
    action = relationship("Action", back_populates="approvals")


class Checkpoint(Base):
    __tablename__ = "checkpoints"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action_id = Column(Integer, ForeignKey("actions.id", ondelete="CASCADE"), nullable=False, index=True)
    approval_id = Column(String(64), nullable=False, index=True)
    
    canonical_payload = Column(Text, nullable=False)
    payload_hash = Column(String(64), nullable=False)
    environment_snapshot = Column(Text, nullable=False)  # JSON serialized snapshot of environment
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    action = relationship("Action", back_populates="checkpoints")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action_id = Column(Integer, ForeignKey("actions.id", ondelete="CASCADE"), nullable=True, index=True)
    approval_id = Column(String(64), nullable=True, index=True)
    
    stage = Column(String(64), nullable=False)  # ANALYSIS, ORCHESTRATION, CLAIM, APPROVAL, RESUME, SECURITY_CHECK, EXECUTION, ATTACK_DEMO
    agent_name = Column(String(64), nullable=False)
    check_name = Column(String(64), nullable=True)
    status = Column(String(16), nullable=False)  # PASS, FAIL, INFO, WARN
    details = Column(Text, nullable=False)
    
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)

    # Relationships
    action = relationship("Action", back_populates="audit_logs")


class EnvironmentState(Base):
    __tablename__ = "environment_state"

    id = Column(Integer, primary_key=True, default=1)
    risk_level = Column(String(32), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    recipient_status = Column(String(32), default="TRUSTED", nullable=False)  # TRUSTED, SUSPICIOUS, BLOCKED
    daily_limit = Column(Float, default=1000000.0, nullable=False)
    transaction_limit = Column(Float, default=200000.0, nullable=False)
    account_status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, FROZEN, RESTRICTED
    
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    role = Column(String(64), default="MANAGER", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
