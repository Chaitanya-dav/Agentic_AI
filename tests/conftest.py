import pytest
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from backend.database import Base, get_db
from backend.models import EnvironmentState, User
from backend.main import app

# In-memory or temporary test SQLite DB
TEST_DATABASE_URL = "sqlite:///./test_secure_execution.db"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_secure_execution.db"):
        try:
            os.remove("./test_secure_execution.db")
        except Exception:
            pass


@pytest.fixture(scope="function")
def db_session():
    """Yields a clean transactional DB session for each test."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    
    # Initialize baseline environment
    env = EnvironmentState(
        id=1,
        risk_level="LOW",
        recipient_status="TRUSTED",
        daily_limit=1000000.0,
        transaction_limit=200000.0,
        account_status="ACTIVE",
    )
    session.add(env)
    session.add_all([
        User(username="alice", role="OPERATOR"),
        User(username="bob", role="MANAGER"),
        User(username="carol", role="SECURITY_ADMIN"),
    ])
    session.commit()

    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI test client with database override."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
