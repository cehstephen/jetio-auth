import pytest
from unittest.mock import MagicMock, AsyncMock
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request
from starlette.exceptions import HTTPException
from jetio_auth.auth_router import LoginSchema

# ===========================================================================
# ROUTER & ROUTE HANDLER TESTS
# ===========================================================================

def test_router_wrapper_methods(auth_router):
    """Verify wrapper methods delegate correctly to the policy."""
    assert callable(auth_router.get_auth_dependency())
    assert callable(auth_router.admin_only())

    from unittest.mock import patch
    with patch("jetio_auth.auth_policy.require_audit_field", return_value="user_id"):
        class DummyModel: pass
        assert callable(auth_router.owner_or_admin(DummyModel))

@pytest.mark.asyncio
async def test_register_route_handlers(auth_router, db, mock_app):
    """Test /register route success and duplicate user error handling."""
    app, routes = mock_app
    auth_router.register_routes(app)
    handler = routes[auth_router.register_path]
    
    # Success Case
    data = auth_router.register_schema(username="route_test", password="pw", age=30)
    res_success = await handler(data, db)
    assert res_success == ({"message": "User created successfully"}, 201)

    # Failure Case (IntegrityError)
    db.commit = AsyncMock(side_effect=IntegrityError("Mock", "params", "orig"))
    db.add = MagicMock()
    db.rollback = AsyncMock()
    
    res_fail = await handler(data, db)
    assert res_fail[1] == 400
    assert "User already exists" in res_fail[0]["error"]
    db.rollback.assert_called_once()

@pytest.mark.asyncio
async def test_login_route_handlers(auth_router, db, mock_app):
    """Test /login route success, invalid credentials, and user not found."""
    app, routes = mock_app
    auth_router.register_routes(app)
    handler = routes[auth_router.login_path]
    
    await auth_router.ensure_admin(db, "login_route", "pass")
    
    # Success Case
    creds = LoginSchema(username="login_route", password="pass")
    res = await handler(creds, db)
    assert "access_token" in res[0]
    
    # Invalid Password
    bad_creds = LoginSchema(username="login_route", password="wrong")
    res = await handler(bad_creds, db)
    assert res == ({"error": "Invalid credentials"}, 401)

    # User Not Found
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    db.execute = AsyncMock(return_value=mock_result)
    
    ghost_creds = LoginSchema(username="ghost", password="pw")
    res_ghost = await handler(ghost_creds, db)
    assert res_ghost == ({"error": "Invalid credentials"}, 401)

@pytest.mark.asyncio
async def test_make_admin_route(auth_router, db, mock_app):
    """Test /make-admin route success and 404 behavior."""
    app, routes = mock_app
    auth_router.register_admin_routes(app)
    route_key = [k for k in routes.keys() if "make-admin" in k][0]
    handler = routes[route_key]
    
    # Success Case
    user = await auth_router.ensure_admin(db, "target", "pw")
    user.is_admin = False 
    await db.commit()
    
    res = await handler(item_id=user.id, db=db, admin_user=user)
    assert res[1] == 200
    
    # Not Found Case
    res_404 = await handler(item_id=9999, db=db, admin_user=user)
    assert res_404[1] == 404

# ===========================================================================
# INTERNAL LOGIC & RACE CONDITIONS
# ===========================================================================

@pytest.mark.asyncio
async def test_ensure_admin_race_condition(auth_router, db):
    """Verify handling of race conditions during admin creation."""
    mock_select = MagicMock()
    mock_select.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_select)

    db.add = MagicMock()
    db.commit = AsyncMock(side_effect=IntegrityError("Mock", "params", "orig"))
    db.rollback = AsyncMock()

    result = await auth_router.ensure_admin(db, "race_admin", "pw")

    assert result is None
    db.rollback.assert_called_once()

def test_internal_validation_errors(auth_router):
    """Verify internal validation for missing admin fields and invalid columns."""
    from tests.conftest import User
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    class Base(DeclarativeBase): pass
    class EmptyModel(Base):
        __tablename__ = "empty"
        id: Mapped[int] = mapped_column(primary_key=True)

    with pytest.raises(ValueError, match="missing an admin flag"):
        auth_router._detect_admin_field(EmptyModel)

    with pytest.raises(ValueError, match="does not have column"):
        auth_router._validate_field(User, "non_existent_column")

# ===========================================================================
# POLICY EDGE CASES
# ===========================================================================

@pytest.mark.asyncio
async def test_policy_id_type_mismatch(auth_router, db):
    """Test policy resilience against ID type mismatches (e.g. string vs int)."""
    policy = auth_router._policy
    from tests.conftest import Question
    
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "Bearer token_valid"

    user = MagicMock(id=1, username="user", is_admin=False)
    item = MagicMock(author_id="bad_id_string") 

    res_user = MagicMock()
    res_user.scalar_one_or_none.return_value = user
    res_item = MagicMock()
    res_item.scalar_one_or_none.return_value = item

    db.execute = AsyncMock(side_effect=[res_user, res_item])
    dep = policy.owner_or_admin(Question)
    
    with pytest.raises(HTTPException) as exc:
        await dep(req, db, item_id=1)
        
    assert exc.value.status_code == 500
    assert "ID type mismatch" in exc.value.detail

@pytest.mark.asyncio
async def test_policy_user_not_found_explicit(auth_router, db):
    """Test policy behavior when user is not found in the database."""
    policy = auth_router._policy
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "Bearer token_valid"

    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=mock_res)

    dep = policy.get_auth_dependency()

    with pytest.raises(HTTPException) as exc:
        await dep(req, db)
    
    assert exc.value.detail == "User not found"
