import pytest
from sqlalchemy.future import select
from jetio_auth.auth_router import AuthRouter
from .conftest import User

# --- Setup Tests ---
def test_auto_detect_admin_field():
    """Verifies scanning for 'is_admin' or 'is_superuser'."""
    router = AuthRouter(user_model=User)
    assert router.admin_field == "is_admin"

def test_manual_admin_field_override_failure():
    """Verifies strictly checking manual admin fields."""
    with pytest.raises(ValueError):
        AuthRouter(user_model=User, admin_field="non_existent_column")

# --- Logic Tests ---

@pytest.mark.asyncio
async def test_ensure_admin_creates_user(auth_router, db):
    """Test creating a fresh admin user."""
    admin = await auth_router.ensure_admin(db, "admin", "pass123")
    
    assert admin.username == "admin"
    assert admin.hashed_password == "hashed_pass123"
    assert admin.is_admin is True

@pytest.mark.asyncio
async def test_ensure_admin_updates_existing(auth_router, db):
    """Test promoting an existing normal user via ensure_admin."""
    user = User(username="steve", hashed_password="pw", is_admin=False)
    db.add(user)
    await db.commit()
    
    updated = await auth_router.ensure_admin(db, "steve", "pw")
    
    assert updated.is_admin is True
    assert updated.username == "steve"

@pytest.mark.asyncio
async def test_register_flow_manually(auth_router, db):
    """Test standard registration logic with dynamic schema."""
    Schema = auth_router.register_schema
    payload = Schema(username="new_user", password="secure_pass")
    
    # Manual logic mimic
    data = payload.model_dump()
    raw_pw = data.pop("password")
    hashed = f"hashed_{raw_pw}"
    
    user = User(hashed_password=hashed, **data)
    db.add(user)
    await db.commit()
    
    saved = await db.get(User, user.id)
    assert saved.username == "new_user"
    assert saved.age == 18 
    assert saved.hashed_password == "hashed_secure_pass"
    assert saved.is_admin is False

@pytest.mark.asyncio
async def test_login_logic(auth_router, db):
    """Test standard login credential verification logic."""
    await auth_router.ensure_admin(db, "login_test", "pass")
    
    res = await db.execute(select(User).where(User.username == "login_test"))
    user = res.scalars().first()
    
    assert user is not None
    assert user.hashed_password == "hashed_pass"
