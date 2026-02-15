import sys
from pathlib import Path
import os
import pytest

# Set testing flag before main import
os.environ["SAKHI_TESTING"] = "1"

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool
from unittest.mock import MagicMock

# Add the project root to sys.path so that tests can import modules
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from main import app
import main
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.types import ARRAY

# Handle ARRAY type in SQLite for testing
@compiles(ARRAY, "sqlite")
def compile_array(element, compiler, **kw):
    return "TEXT"

# Use an in-memory SQLite database for testing
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

@pytest.fixture(name="session")
def session_fixture():
    # Create tables
    SQLModel.metadata.create_all(test_engine)
    with Session(test_engine) as session:
        yield session
    # Drop tables
    SQLModel.metadata.drop_all(test_engine)

from database import SessionLocal

@pytest.fixture(name="client")
def client_fixture(session):
    # Patch the engine in main.py globally for the test session
    original_engine = main.engine
    main.engine = test_engine
    
    # Configure SessionLocal to use the test engine
    # This affects the object essentially everywhere it is imported
    original_bind = SessionLocal.kw['bind']
    SessionLocal.configure(bind=test_engine)
    
    with TestClient(app) as client:
        yield client
        
    # Restore original engine and SessionLocal bind
    main.engine = original_engine
    SessionLocal.configure(bind=original_bind)


@pytest.fixture
def auth_headers(client, session):
    # Create test user
    from models import User
    from main import get_password_hash
    
    user = User(
        name="Test User",
        email="test@example.com",
        password=get_password_hash("password123"),
        role="mother"
    )
    session.add(user)
    session.commit()
    
    # Login to get token
    login_data = {
        "username": "test@example.com", # OAuth2PasswordRequestForm uses username
        "password": "password123"
    }
    # Note: Main.py uses a custom login endpoint accepting JSON LoginSchema
    login_json = {
        "email": "test@example.com",
        "password": "password123"
    }
    
    response = client.post("/login", json=login_json)
    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}
    return {}

@pytest.fixture(autouse=True)
def mock_external_services(monkeypatch):
    """Mock external services to avoid network calls."""
    
    # Mock httpx response class
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self._json_data = json_data
            self.status_code = status_code
            self.text = "Mocked Response"

        def json(self):
            return self._json_data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP Error: {self.status_code}")

    # Mock httpx.post
    def mock_post(url, *args, **kwargs):
        # Mock PPD ML Service
        if "predict" in url or "ppd" in url:
            return MockResponse({
                "probability": 0.15,
                "risk_level": "Low"
            })
        
        # Mock Article Recommendation Service
        if "recommend" in url:
            return MockResponse({
                "recommendations": [
                    {
                        "article_id": "test_art_1",
                        "title": "Test Article",
                        "category": "Wellness",
                        "risk_level": "low",
                        "external_url": "http://test",
                        "access_type": "Free",
                        "score": 0.9
                    }
                ]
            })
        return MockResponse({})

    monkeypatch.setattr("httpx.post", mock_post)
    
    # Mock httpx.get for OpenAPI discovery
    def mock_get(url, *args, **kwargs):
        if "openapi.json" in url:
             return MockResponse({
                "paths": {
                    "/predict": {"post": {}}
                }
            })
        return MockResponse({})
        
    monkeypatch.setattr("httpx.get", mock_get)

    # Mock Firebase
    monkeypatch.setattr("main.firebase_app", None)
    monkeypatch.setattr("main.generate_firebase_token", lambda uid: "mock_firebase_token")
    
    # Mock Email sending
    monkeypatch.setattr("smtplib.SMTP", MagicMock())
