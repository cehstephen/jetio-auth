import pytest
import asyncio
import sys
from unittest.mock import MagicMock

# --- Mock Jetio Dependencies ---
mock_jetio = MagicMock()
mock_jetio.framework.Depends = lambda x: x
mock_jetio.framework.JsonResponse = lambda data, status_code=200: (data, status_code)

def mock_get_password_hash(password: str) -> str:
    return f"hashed_{password}"

def mock_verify_password(plain: str, hashed: str) -> bool:
    return hashed == f"hashed_{plain}"

def mock_create_access_token(data: dict) -> str:
    return f"token_{data.get('sub')}"

def mock_decode_access_token(token: str) -> dict:
    if token.startswith("token_"):
        return {"sub": token.replace("token_", "")}
    return None

def mock_require_audit_field(model, audit_fields=None):
    return "author_id"

mock_jetio.auth.get_password_hash = mock_get_password_hash
mock_jetio.auth.verify_password = mock_verify_password
mock_jetio.auth.create_access_token = mock_create_access_token
mock_jetio.auth.decode_access_token = mock_decode_access_token
mock_jetio.security.require_audit_field = mock_require_audit_field

sys.modules["jetio"] = mock_jetio
sys.modules["jetio.auth"] = mock_jetio.auth
sys.modules["jetio.framework"] = mock_jetio.framework
sys.modules["jetio.security"] = mock_jetio.security

# --- Real Imports ---
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool
from jetio_auth.mixins import JetioAuthMixin
from jetio_auth.auth_router import AuthRouter

# --- Test Models ---
class Base(DeclarativeBase):
    pass

class User(Base, JetioAuthMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str] = mapped_column(default="test@test.com")
    age: Mapped[int] = mapped_column(default=18)

class Question(Base):
    __tablename__ = "questions"
    id: Mapped[int] = mapped_column(primary_key=True)
    content: Mapped[str] = mapped_column()
    author_id: Mapped[int] = mapped_column() 

# --- Fixtures ---
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def db(engine):
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
def auth_router():
    return AuthRouter(user_model=User)

@pytest.fixture
def mock_app():
    """
    Captures routes registered by AuthRouter for testing.
    Returns: (app_mock, routes_dict)
    """
    app = MagicMock()
    routes = {}

    def route_side_effect(path, methods=None):
        def decorator(func):
            routes[path] = func
            return func
        return decorator

    app.route.side_effect = route_side_effect
    return app, routes
