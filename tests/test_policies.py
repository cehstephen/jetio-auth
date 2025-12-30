import pytest
from starlette.requests import Request
from starlette.exceptions import HTTPException
from unittest.mock import MagicMock
from tests.conftest import User, Question
import jetio.auth

# ===========================================================================
# FIXTURES
# ===========================================================================

@pytest.fixture
def policy(auth_router):
    return auth_router._policy

# ===========================================================================
# HAPPY PATHS (Standard Logic)
# ===========================================================================

@pytest.mark.asyncio
async def test_auth_dependency_validates_token(policy, db):
    """Ensure the JWT token is decoded and user is fetched."""
    user = User(username="valid_user", hashed_password="pw")
    db.add(user)
    await db.commit()
    
    request = MagicMock(spec=Request)
    request.headers.get.return_value = "Bearer token_valid_user"
    
    dep = policy.get_auth_dependency()
    resolved_user = await dep(request, db)
    
    assert resolved_user.username == "valid_user"

@pytest.mark.asyncio
async def test_admin_only_policy(policy, db):
    """Test that admin_only blocks standard users."""
    admin = User(username="admin_pol", hashed_password="pw", is_admin=True)
    pleb = User(username="pleb", hashed_password="pw", is_admin=False)
    db.add_all([admin, pleb])
    await db.commit()
    
    dep = policy.admin_only()
    
    # Test Admin Access
    req_admin = MagicMock(spec=Request)
    req_admin.headers.get.return_value = "Bearer token_admin_pol"
    assert await dep(req_admin, db) == admin
    
    # Test User Access (Should Fail)
    req_pleb = MagicMock(spec=Request)
    req_pleb.headers.get.return_value = "Bearer token_pleb"
    with pytest.raises(HTTPException) as exc:
        await dep(req_pleb, db)
    assert exc.value.status_code == 403

@pytest.mark.asyncio
async def test_owner_or_admin_logic(policy, db):
    """
    Test the hybrid policy used for Question/Answer updates.
    Allows Author OR Admin.
    """
    owner = User(username="owner", hashed_password="pw", is_admin=False)
    admin = User(username="admin_oa", hashed_password="pw", is_admin=True)
    stranger = User(username="stranger", hashed_password="pw", is_admin=False)
    db.add_all([owner, admin, stranger])
    await db.commit()
    
    question = Question(content="Help?", author_id=owner.id)
    db.add(question)
    await db.commit()
    
    dep = policy.owner_or_admin(Question)
    
    # Test Owner Access
    req_owner = MagicMock(spec=Request)
    req_owner.headers.get.return_value = "Bearer token_owner"
    res = await dep(req_owner, db, item_id=question.id)
    assert res.username == "owner"
    
    # Test Admin Access
    req_admin = MagicMock(spec=Request)
    req_admin.headers.get.return_value = "Bearer token_admin_oa"
    res = await dep(req_admin, db, item_id=question.id)
    assert res.username == "admin_oa"
    
    # Test Stranger Access (Should Fail)
    req_stranger = MagicMock(spec=Request)
    req_stranger.headers.get.return_value = "Bearer token_stranger"
    with pytest.raises(HTTPException) as exc:
        await dep(req_stranger, db, item_id=question.id)
    assert exc.value.status_code == 403

# ===========================================================================
# EDGE CASES (Errors & Invalid States)
# ===========================================================================

@pytest.mark.asyncio
async def test_policy_missing_auth_header(policy, db):
    """Test behavior when Authorization header is missing or malformed."""
    req = MagicMock(spec=Request)
    dep = policy.get_auth_dependency()
    
    # 1. No Header
    req.headers.get.return_value = None
    with pytest.raises(HTTPException) as exc:
        await dep(req, db)
    assert exc.value.status_code == 401
    
    # 2. Malformed Header (No 'Bearer ')
    req.headers.get.return_value = "Basic 12345"
    with pytest.raises(HTTPException) as exc:
        await dep(req, db)
    assert exc.value.status_code == 401

@pytest.mark.asyncio
async def test_policy_invalid_token(policy, db):
    """Test behavior when token cannot be decoded."""
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "Bearer invalid_token_string"
    
    # Mock decode to return None
    original_decode = jetio.auth.decode_access_token
    jetio.auth.decode_access_token = lambda x: None
    
    try:
        dep = policy.get_auth_dependency()
        with pytest.raises(HTTPException) as exc:
            await dep(req, db)
        assert exc.value.detail == "Invalid token"
    finally:
        # Restore the original function
        jetio.auth.decode_access_token = original_decode

@pytest.mark.asyncio
async def test_policy_user_deleted(policy, db):
    """Test behavior when token is valid but user no longer exists in DB."""
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "Bearer token_deleted_user"
    
    # User does NOT exist in DB
    dep = policy.get_auth_dependency()
    with pytest.raises(HTTPException) as exc:
        await dep(req, db)
    assert exc.value.detail == "User not found"

@pytest.mark.asyncio
async def test_owner_security_misconfig(policy, db):
    """Test safety check: PUT/DELETE must have item_id injected."""
    user = User(username="hacker", hashed_password="pw")
    db.add(user)
    await db.commit()
    
    req = MagicMock(spec=Request)
    req.method = "DELETE"
    req.headers.get.return_value = "Bearer token_hacker"
    
    dep = policy.owner_or_admin(Question)
    
    # item_id is None by default in the dependency signature
    with pytest.raises(HTTPException) as exc:
        await dep(req, db, item_id=None)
    assert exc.value.status_code == 500
    assert "Security misconfiguration" in exc.value.detail

@pytest.mark.asyncio
async def test_owner_post_creation(policy, db):
    """Test that POST requests (creating new items) skip ownership checks."""
    user = User(username="creator", hashed_password="pw")
    db.add(user)
    await db.commit()
    
    req = MagicMock(spec=Request)
    req.method = "POST"
    req.headers.get.return_value = "Bearer token_creator"
    
    dep = policy.owner_or_admin(Question)
    result = await dep(req, db, item_id=None)
    assert result == user
