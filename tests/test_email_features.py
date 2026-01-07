import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from jetio_auth.auth_router import AuthRouter, ForgotPasswordSchema, LoginSchema, ResetPasswordSchema
from jetio_auth.tokens import generate_token, sha256_hex, expires_in_minutes
from .conftest import FullUser

# -----------------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------------
async def process_background_tasks():
    """
    Yields control to the event loop to allow scheduled background tasks 
    (such as email sending) to execute before assertion verification.
    """
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
@patch("jetio_auth.auth_router.JetioAuthEmailService")
async def test_registration_sends_activation_email(MockEmailService, db, mock_app):
    """
    Verifies that registering a new user triggers the activation email background task.
    """
    email_router = AuthRouter(user_model=FullUser, require_verified_email=True)
    
    app, routes = mock_app
    email_router.register_routes(app)
    handler = routes["/register"]

    # Configure the mock email service
    mock_email_instance = email_router.email_service
    mock_email_instance.send_activation_email = AsyncMock()

    # Create user
    data = email_router.register_schema(username="activate_me", password="pw", email="test@example.com")
    response, status = await handler(data, db)

    assert status == 201
    assert "check your email" in response["message"]

    # Allow background tasks to complete
    await process_background_tasks()

    # Verify email was sent
    mock_email_instance.send_activation_email.assert_called_once()

    # Verify user state in DB
    user = await db.get(FullUser, 1)
    assert user.email_confirmed is False
    assert user.email_confirmation_token_hash is not None


@pytest.mark.asyncio
async def test_unverified_user_cannot_login(db, mock_app):
    """
    Ensures that unconfirmed users are blocked from logging in when 
    `require_verified_email` is set to True.
    """
    email_router = AuthRouter(user_model=FullUser, require_verified_email=True)

    app, routes = mock_app
    email_router.register_routes(app)
    register_handler = routes["/register"]
    login_handler = routes["/login"]

    # 1. Create the user
    data = email_router.register_schema(username="unverified", password="pw", email="test@test.com")
    await register_handler(data, db)

    # 2. Attempt to log in
    login_data = LoginSchema(username="unverified", password="pw")
    response, status = await login_handler(login_data, db)

    assert status == 403
    assert "Account not verified" in response["error"]


@pytest.mark.asyncio
@patch("jetio_auth.auth_router.JetioAuthEmailService")
async def test_account_activation_flow(MockEmailService, db, mock_app):
    """
    End-to-end test: Registration, token capture, activation, and successful login.
    """
    email_router = AuthRouter(user_model=FullUser, require_verified_email=True)
    
    app, routes = mock_app
    email_router.register_routes(app)
    register_handler = routes["/register"]
    activate_handler = routes["/activate/{token}"]
    login_handler = routes["/login"]

    # Mock the email service to capture the sent token
    token_capture = {}
    async def capture_token(to_email, *, activation_link, **kwargs):
        token_capture["token"] = activation_link.split("/")[-1]
    
    mock_email_instance = email_router.email_service
    mock_email_instance.send_activation_email = AsyncMock(side_effect=capture_token)

    # 1. Register
    data = email_router.register_schema(username="activation_flow", password="pw", email="flow@test.com")
    await register_handler(data, db)
    
    # Allow background tasks to capture the token
    await process_background_tasks()
    
    assert "token" in token_capture

    # 2. Activate
    response, status = await activate_handler(token=token_capture["token"], db=db)
    assert status == 200
    assert "verified successfully" in response["message"]

    user = await db.get(FullUser, 1)
    await db.refresh(user)
    assert user.email_confirmed is True
    assert user.email_confirmed_at is not None
    assert user.email_confirmation_token_hash is None

    # 3. Log in
    login_data = LoginSchema(username="activation_flow", password="pw")
    response, status = await login_handler(login_data, db)
    assert status == 200
    assert "access_token" in response


@pytest.mark.asyncio
@patch("jetio_auth.auth_router.JetioAuthEmailService")
async def test_forgot_password_flow(MockEmailService, db, mock_app):
    """
    End-to-end test for password reset: Request reset, capture token, and update password.
    """
    email_router = AuthRouter(user_model=FullUser, require_verified_email=True)
    
    app, routes = mock_app
    email_router.register_routes(app)
    register_handler = routes["/register"]
    forgot_handler = routes["/forgot-password"]
    reset_handler = routes["/reset-password"]
    login_handler = routes["/login"]

    # Mock email service to capture the reset token
    token_capture = {}
    async def capture_reset_token(to_email, reset_link, **kwargs):
        token_capture["token"] = reset_link.split("/")[-1]

    mock_email_instance = email_router.email_service
    mock_email_instance.send_password_reset_email = AsyncMock(side_effect=capture_reset_token)
    mock_email_instance.send_activation_email = AsyncMock()
    mock_email_instance.send_custom_email = AsyncMock()

    # 1. Create an active user
    reg_data = email_router.register_schema(username="reset_me", password="old_password", email="reset@test.com")
    await routes["/register"](reg_data, db)
    
    # Clear pending registration tasks
    await process_background_tasks()
    
    user = await db.get(FullUser, 1)
    user.email_confirmed = True 
    await db.commit()

    old_hashed_password = user.hashed_password

    # 2. Request password reset
    forgot_data = ForgotPasswordSchema(identity="reset@test.com")
    response, status = await forgot_handler(forgot_data, db)
    assert status == 200
    
    # Allow background tasks to send the reset email
    await process_background_tasks()
    
    user_after_request = await db.get(FullUser, 1)
    await db.refresh(user_after_request)
    assert user_after_request.password_reset_token_hash is not None
    assert "token" in token_capture

    # 3. Use the token to reset the password
    reset_data = ResetPasswordSchema(token=token_capture["token"], new_password="new_password")
    response, status = await reset_handler(reset_data, db)
    assert status == 200

    # Allow success email task to complete
    await process_background_tasks()

    user_after_reset = await db.get(FullUser, 1)
    assert user_after_reset.password_reset_token_hash is None
    # Hashed password should be updated
    assert user_after_reset.hashed_password != old_hashed_password

    # 4. Log in with the new password
    login_data = LoginSchema(username="reset_me", password="new_password")
    response, status = await login_handler(login_data, db)
    assert status == 200
    assert "access_token" in response

    # 5. Old password should no longer work
    login_data_old = LoginSchema(username="reset_me", password="old_password")
    response, status = await login_handler(login_data_old, db)
    assert status == 401