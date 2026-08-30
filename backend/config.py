import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "Agentic AI Secure Approval & Execution System"
    APP_ENV: str = "development"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "sqlite:///./secure_execution.db"
    
    # Security & Tokens
    SECRET_KEY: str = "super-secret-cryptographic-signing-key-2026"
    APPROVAL_EXPIRY_SECONDS: int = 3600  # 1 hour
    
    # LLM Settings
    OPENAI_API_KEY: Optional[str] = None
    LLM_PROVIDER: str = "openai"  # openai, mock
    LLM_MODEL: str = "gpt-4o-mini"
    USE_MOCK_LLM: bool = True  # Defaults to True for zero-config offline reliability
    
    # Business Rules Baseline
    AUTO_APPROVE_THRESHOLD: float = 1000.0
    HIGH_RISK_THRESHOLD: float = 25000.0
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()

# Auto-detect if OPENAI_API_KEY is provided in env
if os.getenv("OPENAI_API_KEY") and os.getenv("USE_MOCK_LLM", "").lower() not in ("1", "true"):
    settings.USE_MOCK_LLM = False
    settings.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
