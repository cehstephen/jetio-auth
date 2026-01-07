# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

import logging
import asyncio
from typing import Optional, Any, Dict

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.inspection import inspect
from pydantic import BaseModel

# Core Jetio Imports
from jetio.auth import get_password_hash, verify_password, create_access_token
from jetio.framework import Depends, JsonResponse, Response
from jetio.config import settings

# Local Plugin Imports
from .auth_policy import AuthPolicy
from .utils import create_register_schema
from .tokens import generate_token, sha256_hex, expires_in_minutes, is_expired, utcnow
from .email_service import JetioAuthEmailService

# Configure module-level logger
logger = logging.getLogger(__name__)


# =============================================================================
# Schemas
# =============================================================================

class LoginSchema(BaseModel):
    username: str
    password: str


class ForgotPasswordSchema(BaseModel):
    """
    Public schema: the identifier the user enters to locate their account.
    """
    identity: str


class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str


# =============================================================================
# Router
# =============================================================================

class AuthRouter:
    """
    Unified authentication and authorization router for Jetio applications.
    
    Implements asynchronous background email delivery using asyncio.create_task
    to ensure non-blocking responses without external dependencies.
    """

    def __init__(
        self,
        user_model,
        admin_field: Optional[str] = None,
        login_path: str = "/login",
        register_path: str = "/register",
        *,
        identity_field: Optional[str] = None,
        email_field: str = "email",
        require_verified_email: bool = False,
        confirmation_ttl_minutes: int = 60 * 24,  # 24h
        reset_ttl_minutes: int = 30,              # 30m
    ):
        self.user_model = user_model
        self.login_path = login_path
        self.register_path = register_path

        self.identity_field = identity_field
        self.email_field = email_field
        self.require_verified_email = require_verified_email
        self.confirmation_ttl_minutes = confirmation_ttl_minutes
        self.reset_ttl_minutes = reset_ttl_minutes

        # Built-in email service (uses jetio.config.settings)
        self.email_service = JetioAuthEmailService()

        # 1) AUTO-DISCOVERY: Find the admin field
        if admin_field:
            self._validate_field(user_model, admin_field)
            self.admin_field = admin_field
        else:
            self.admin_field = self._detect_admin_field(user_model)

        # 2) DYNAMIC SCHEMA: Generate Pydantic model for registration
        self.register_schema = create_register_schema(user_model)

        # 3) POLICY: Initialize policy with the detected admin field
        self._policy = AuthPolicy(user_model, admin_field=self.admin_field)

        # 4) VALIDATION: Fail-fast if misconfigured
        self._validate_capabilities()

    # -------------------------------------------------------------------------
    # Introspection helpers
    # -------------------------------------------------------------------------

    def _detect_admin_field(self, model) -> str:
        mapper = inspect(model)
        candidates = ["is_admin", "is_superuser", "is_staff", "is_master"]

        for name in candidates:
            if name in mapper.all_orm_descriptors:
                return name

        raise ValueError(
            f"Model '{model.__name__}' is missing an admin flag. "
            f"Please add 'is_admin: Mapped[bool]' or explicitly pass admin_field='your_col'."
        )

    def _validate_field(self, model, field_name: str):
        mapper = inspect(model)
        if field_name not in mapper.all_orm_descriptors:
            raise ValueError(f"Model '{model.__name__}' does not have column '{field_name}'")

    def _has_columns(self, *names: str) -> bool:
        mapper = inspect(self.user_model)
        for n in names:
            if n in mapper.all_orm_descriptors:
                continue
            if not hasattr(self.user_model, n):
                return False
        return True

    # -------------------------------------------------------------------------
    # Capability detection
    # -------------------------------------------------------------------------

    def _email_confirmation_enabled(self) -> bool:
        return self._has_columns(
            "email_confirmed",
            "email_confirmed_at",
            "email_confirmation_token_hash",
            "email_confirmation_expires_at",
        )

    def _password_reset_enabled(self) -> bool:
        return self._has_columns("password_reset_token_hash", "password_reset_expires_at")

    def _password_auth_enabled(self) -> bool:
        return self._has_columns("hashed_password")

    def _resolve_identity_field(self) -> str:
        if self.identity_field:
            self._validate_field(self.user_model, self.identity_field)
            return self.identity_field

        mapper = inspect(self.user_model)
        if "email" in mapper.all_orm_descriptors:
            return "email"
        if "username" in mapper.all_orm_descriptors:
            return "username"

        raise ValueError(
            f"Model '{self.user_model.__name__}' has no 'email' or 'username' field. "
            "Add an identity column or pass identity_field='your_col'."
        )

    def _resolve_email_field(self) -> str:
        self._validate_field(self.user_model, self.email_field)
        return self.email_field

    # -------------------------------------------------------------------------
    # Professional validation (fail-fast)
    # -------------------------------------------------------------------------

    def _validate_capabilities(self) -> None:
        if not self._password_auth_enabled():
            raise ValueError(
                f"Model '{self.user_model.__name__}' is missing 'hashed_password'. "
                "Add JetioAuthMixin (or JetioFullAuthMixin)."
            )

        # If any email-sending feature is enabled, email delivery field must exist
        if self._email_confirmation_enabled() or self._password_reset_enabled():
            _ = self._resolve_email_field()

        # Features that perform user lookup require an identity field
        if self._email_confirmation_enabled() or self._password_reset_enabled():
            _ = self._resolve_identity_field()

        if self._email_confirmation_enabled() and self.confirmation_ttl_minutes <= 0:
            raise ValueError("confirmation_ttl_minutes must be > 0")

        if self._password_reset_enabled() and self.reset_ttl_minutes <= 0:
            raise ValueError("reset_ttl_minutes must be > 0")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _absolute_link(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{settings.DOMAIN}{path}"

    async def _safe_send_activation(self, to_email: str, link: str):
        """Wrapper to log errors during background execution."""
        try:
            await self.email_service.send_activation_email(
                to_email,
                activation_link=link,
                company_name="Jetio App",
            )
        except Exception as e:
            logger.error(f"Failed to send activation email to {to_email}: {e}")

    async def _safe_send_reset(self, to_email: str, link: str):
        """Wrapper to log errors during background execution."""
        try:
            await self.email_service.send_password_reset_email(to_email, link)
        except Exception as e:
            logger.error(f"Failed to send password reset email to {to_email}: {e}")

    async def _safe_send_reset_success(self, to_email: str):
        """Wrapper to log errors during background execution."""
        try:
            await self.email_service.send_custom_email(
                to_email,
                subject="Your password has been changed",
                template_name="password_reset_success.html",
                context={},
            )
        except Exception as e:
            logger.error(f"Failed to send password reset success email to {to_email}: {e}")

    # ========================================================================
    # ROUTES
    # ========================================================================

    def register_routes(self, app):
        RegisterSchema = self.register_schema

        identity_field: Optional[str] = None
        email_field: Optional[str] = None

        if self._email_confirmation_enabled() or self._password_reset_enabled():
            identity_field = self._resolve_identity_field()
            email_field = self._resolve_email_field()

        @app.route(self.register_path, methods=["POST"])
        async def register(user_data: RegisterSchema, db: AsyncSession):
            # Use model_dump() for Pydantic V2 compatibility
            data = user_data.model_dump()
            raw_password = data.pop("password")
            hashed = get_password_hash(raw_password)

            new_user = self.user_model(hashed_password=hashed, **data)

            confirmation_token: Optional[str] = None
            if self._email_confirmation_enabled():
                confirmation_token = generate_token()
                new_user.email_confirmed = False
                new_user.email_confirmed_at = None
                new_user.email_confirmation_token_hash = sha256_hex(confirmation_token)
                new_user.email_confirmation_expires_at = expires_in_minutes(self.confirmation_ttl_minutes)

            try:
                db.add(new_user)
                await db.commit()
                await db.refresh(new_user)
            except IntegrityError:
                await db.rollback()
                return JsonResponse(
                    {"error": "User already exists (Unique constraint failed)"},
                    status_code=400,
                )

            # Fire-and-forget background email task
            if confirmation_token is not None and email_field is not None:
                to_email = str(getattr(new_user, email_field))
                activation_link = self._absolute_link(f"/activate/{confirmation_token}")
                
                asyncio.create_task(self._safe_send_activation(to_email, activation_link))

                return JsonResponse(
                    {"message": "User created. Please check your email to verify your account."},
                    status_code=201,
                )

            return JsonResponse({"message": "User created successfully"}, status_code=201)

        @app.route(self.login_path, methods=["POST"])
        async def login(user_data: LoginSchema, db: AsyncSession):
            result = await db.execute(
                select(self.user_model).where(self.user_model.username == user_data.username)
            )
            user = result.scalars().first()
            
            if not user or not verify_password(user_data.password, user.hashed_password):
                return JsonResponse({"error": "Invalid credentials"}, status_code=401)

            if self._email_confirmation_enabled() and self.require_verified_email:
                if not bool(getattr(user, "email_confirmed", False)):
                    return JsonResponse(
                        {"error": "Account not verified. Please check your email."},
                        status_code=403,
                    )

            token = create_access_token(data={"sub": user.username})
            return JsonResponse({"access_token": token, "token_type": "bearer"}, status_code=200)

        # ---------------------------------------------------------------------
        # Email confirmation activation route
        # ---------------------------------------------------------------------
        if self._email_confirmation_enabled():

            @app.route("/activate/{token}", methods=["GET"])
            async def activate_account(token: str, db: AsyncSession):
                token_hash = sha256_hex(token)
                result = await db.execute(
                    select(self.user_model).where(
                        self.user_model.email_confirmation_token_hash == token_hash
                    )
                )
                user = result.scalars().first()
                if not user:
                    return JsonResponse({"error": "Invalid activation token."}, status_code=404)

                if is_expired(getattr(user, "email_confirmation_expires_at", None)):
                    return JsonResponse({"error": "Activation token expired."}, status_code=400)

                user.email_confirmed = True
                user.email_confirmed_at = utcnow()
                user.email_confirmation_token_hash = None
                user.email_confirmation_expires_at = None

                await db.commit()
                await db.refresh(user)
                return JsonResponse({"message": "Account verified successfully."}, status_code=200)

        # ---------------------------------------------------------------------
        # Password reset routes
        # ---------------------------------------------------------------------
        if self._password_reset_enabled():
            assert identity_field is not None
            assert email_field is not None

            @app.route("/forgot-password", methods=["POST"])
            async def forgot_password(payload: ForgotPasswordSchema, db: AsyncSession):
                generic = {"message": "If the account exists, a reset email has been sent."}

                result = await db.execute(
                    select(self.user_model).where(
                        getattr(self.user_model, identity_field) == str(payload.identity)
                    )
                )
                user = result.scalars().first()
                
                # Return success even if user not found to prevent enumeration
                if not user:
                    return JsonResponse(generic, status_code=200)

                reset_token = generate_token()
                user.password_reset_token_hash = sha256_hex(reset_token)
                user.password_reset_expires_at = expires_in_minutes(self.reset_ttl_minutes)

                await db.commit()
                await db.refresh(user)

                # Fire-and-forget background email task
                to_email = str(getattr(user, email_field))
                reset_link = self._absolute_link(f"/reset-password/{reset_token}")
                
                asyncio.create_task(self._safe_send_reset(to_email, reset_link))

                return JsonResponse(generic, status_code=200)

            @app.route("/reset-password/{token}", methods=["GET"])
            async def reset_password_link(token: str):
                """Renders a password reset form with client-side password confirmation."""
                html_content = f"""
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Reset Password</title>
                    <style>
                        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8f9fa; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                        .card {{ background: white; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); width: 100%; max-width: 400px; }}
                        h2 {{ margin-top: 0; color: #1a1a1a; font-size: 1.5rem; text-align: center; margin-bottom: 1.5rem; }}
                        label {{ display: block; margin-bottom: 0.5rem; color: #4a5568; font-size: 0.875rem; font-weight: 500; }}
                        input {{ width: 100%; padding: 0.75rem; margin-bottom: 1.25rem; border: 1px solid #e2e8f0; border-radius: 6px; box-sizing: border-box; font-size: 1rem; transition: border-color 0.2s; }}
                        input:focus {{ outline: none; border-color: #3182ce; box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.1); }}
                        button {{ width: 100%; padding: 0.75rem; background-color: #3182ce; color: white; border: none; border-radius: 6px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background-color 0.2s; }}
                        button:hover {{ background-color: #2b6cb0; }}
                        .meta {{ text-align: center; margin-top: 1.5rem; color: #718096; font-size: 0.875rem; }}
                        #message {{ display: none; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 0.9rem; text-align: center; }}
                        .error {{ background-color: #fed7d7; color: #c53030; }}
                        .success {{ background-color: #c6f6d5; color: #2f855a; }}
                    </style>
                </head>
                <body>
                    <div class="card">
                        <h2>Set New Password</h2>
                        <div id="message"></div>
                        <form id="resetForm">
                            <input type="hidden" id="token" name="token" value="{token}">
                            <label for="new_password">New Password</label>
                            <input type="password" id="new_password" name="new_password" placeholder="Enter new password" required autofocus>
                            <label for="confirm_password">Confirm Password</label>
                            <input type="password" id="confirm_password" name="confirm_password" placeholder="Re-type new password" required>
                            <button type="submit" id="submitBtn">Update Password</button>
                        </form>
                        <div class="meta">
                            This link expires in {self.reset_ttl_minutes} minutes.
                        </div>
                    </div>
                    <script>
                        document.getElementById('resetForm').addEventListener('submit', async function(e) {{
                            e.preventDefault();
                            const btn = document.getElementById('submitBtn');
                            const msgDiv = document.getElementById('message');
                            const token = document.getElementById('token').value;
                            const password = document.getElementById('new_password').value;
                            const confirm = document.getElementById('confirm_password').value;

                            // Reset UI
                            btn.disabled = true;
                            btn.innerText = "Updated";
                            msgDiv.style.display = 'none';
                            msgDiv.className = '';

                            if (password !== confirm) {{
                                msgDiv.innerText = "Passwords do not match. Please try again.";
                                msgDiv.className = 'error';
                                msgDiv.style.display = 'block';
                                btn.disabled = false;
                                btn.innerText = "Update Password";
                                return;
                            }}

                            try {{
                                const response = await fetch('/reset-password', {{
                                    method: 'POST',
                                    headers: {{ 'Content-Type': 'application/json' }},
                                    body: JSON.stringify({{ token: token, new_password: password }})
                                }});
                                const result = await response.json();
                                if (response.ok) {{
                                    msgDiv.innerText = "Password reset successfully! You can now log in.";
                                    msgDiv.className = 'success';
                                    msgDiv.style.display = 'block';
                                    document.getElementById('resetForm').reset();
                                }} else {{
                                    throw new Error(result.error || result.detail || 'An error occurred');
                                }}
                            }} catch (error) {{
                                msgDiv.innerText = error.message;
                                msgDiv.className = 'error';
                                msgDiv.style.display = 'block';
                                btn.disabled = false;
                                btn.innerText = "Update Password";
                            }}
                        }});
                    </script>
                </body>
                </html>
                """
                return Response(html_content, status_code=200)

            @app.route("/reset-password", methods=["POST"])
            async def reset_password(payload: ResetPasswordSchema, db: AsyncSession):
                token_hash = sha256_hex(payload.token)
                result = await db.execute(
                    select(self.user_model).where(
                        self.user_model.password_reset_token_hash == token_hash
                    )
                )
                user = result.scalars().first()
                if not user:
                    return JsonResponse({"error": "Invalid token."}, status_code=400)

                if is_expired(getattr(user, "password_reset_expires_at", None)):
                    return JsonResponse({"error": "Token expired."}, status_code=400)

                user.hashed_password = get_password_hash(payload.new_password)
                user.password_reset_token_hash = None
                user.password_reset_expires_at = None

                await db.commit()
                await db.refresh(user)

                # Fire-and-forget background email task
                to_email = str(getattr(user, email_field))
                asyncio.create_task(self._safe_send_reset_success(to_email))

                return JsonResponse({"message": "Password reset successfully."}, status_code=200)

    def register_admin_routes(self, app, path="/admin/{item_id:int}/make-admin"):
        admin_dep = self.admin_only()

        @app.route(path, methods=["POST"])
        async def make_admin(
            item_id: int,
            db: AsyncSession,
            admin_user: Any = Depends(admin_dep),
        ):
            target_user = await db.get(self.user_model, int(item_id))
            if not target_user:
                return JsonResponse({"error": "User not found"}, status_code=404)

            setattr(target_user, self.admin_field, True)

            target_user_id = int(target_user.id)
            await db.commit()

            return JsonResponse(
                {"message": "User promoted to admin", "user_id": target_user_id},
                status_code=200,
            )

    # ========================================================================
    # HELPERS
    # ========================================================================

    async def ensure_admin(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        email: str = "admin@example.com",
    ):
        result = await db.execute(
            select(self.user_model).where(self.user_model.username == username)
        )
        existing = result.scalar_one_or_none()

        if existing:
            if not getattr(existing, self.admin_field, False):
                setattr(existing, self.admin_field, True)
                await db.commit()
            return existing

        user_data: Dict[str, Any] = {
            "username": username,
            "hashed_password": get_password_hash(password),
            "email": email,
            self.admin_field: True,
        }

        try:
            admin = self.user_model(**user_data)
            db.add(admin)
            await db.commit()
            return admin
        except IntegrityError:
            await db.rollback()
            return existing

    # ========================================================================
    # AUTHORIZATION POLICIES
    # ========================================================================

    def get_auth_dependency(self):
        return self._policy.get_auth_dependency()

    def owner_or_admin(self, resource_model, audit_fields: Optional[list] = None):
        return self._policy.owner_or_admin(resource_model, audit_fields)

    def admin_only(self):
        return self._policy.admin_only()