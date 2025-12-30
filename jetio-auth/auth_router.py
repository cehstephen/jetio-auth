# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

from typing import Optional, Any, List
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.inspection import inspect
from pydantic import BaseModel
from starlette.requests import Request

# Core Jetio Imports
from jetio.auth import get_password_hash, verify_password, create_access_token
from jetio.framework import Depends, JsonResponse

# Local Plugin Imports
from .auth_policy import AuthPolicy
from .utils import create_register_schema

# Define a standard schema for login (since Registration is dynamic)
class LoginSchema(BaseModel):
    username: str
    password: str

class AuthRouter:
    """
    Unified authentication and authorization router for Jetio applications.
    
    Features:
    - Auto-detects admin fields (is_admin, is_superuser, etc.) to configure policies.
    - Generates dynamic Pydantic schemas for registration based on the User model.
    - Centralized Auth Policy management for routes and dependencies.
    """
    
    def __init__(
        self, 
        user_model, 
        admin_field: Optional[str] = None, # Allow override, but default to auto-detect
        login_path: str = "/login", 
        register_path: str = "/register"
    ):
        self.user_model = user_model
        self.login_path = login_path
        self.register_path = register_path

        # 1. AUTO-DISCOVERY: Find the admin field
        if admin_field:
            self._validate_field(user_model, admin_field)
            self.admin_field = admin_field
        else:
            self.admin_field = self._detect_admin_field(user_model)

        # 2. DYNAMIC SCHEMA: Generate Pydantic model for registration
        self.register_schema = create_register_schema(user_model)
        
        # 3. POLICY: Initialize policy with the detected admin field
        self._policy = AuthPolicy(user_model, admin_field=self.admin_field)

    def _detect_admin_field(self, model) -> str:
        """
        Scans for the first matching standard admin flag.
        Returns the name of the column to use as the Single Source of Truth.
        """
        mapper = inspect(model)
        candidates = ["is_admin", "is_superuser", "is_staff", "is_master"]
        
        for name in candidates:
            if name in mapper.all_orm_descriptors:
                return name
        
        # Fail Fast if nothing standard is found
        raise ValueError(
            f"Model '{model.__name__}' is missing an admin flag. "
            f"Please add 'is_admin: Mapped[bool]' or explicitly pass admin_field='your_col'."
        )

    def _validate_field(self, model, field_name: str):
        """Strict check for manual overrides."""
        mapper = inspect(model)
        if field_name not in mapper.all_orm_descriptors:
             raise ValueError(f"Model '{model.__name__}' does not have column '{field_name}'")

    # ========================================================================
    # ROUTES
    # ========================================================================

    def register_routes(self, app):
        # Use the dynamic schema for registration
        RegisterSchema = self.register_schema

        @app.route(self.register_path, methods=["POST"])
        async def register(user_data: RegisterSchema, db: AsyncSession):
            # 1. Convert to dict
            data = user_data.dict()
            
            # 2. Pop the raw password (not needed for DB)
            raw_password = data.pop("password")
            
            # 3. Hash it
            hashed = get_password_hash(raw_password)
            
            # 4. Create DB model dynamically
            new_user = self.user_model(
                hashed_password=hashed, 
                **data
            )
            
            # 5. Save with Integrity Check
            # Catches duplicate usernames/emails without needing a pre-select query.
            try:
                db.add(new_user)
                await db.commit()
            except IntegrityError:
                await db.rollback()
                return JsonResponse(
                    {"error": "User already exists (Unique constraint failed)"}, 
                    status_code=400
                )
            
            return {"message": "User created successfully"}, 201

        @app.route(self.login_path, methods=["POST"])
        async def login(user_data: LoginSchema, db: AsyncSession):
            result = await db.execute(
                select(self.user_model).where(
                    self.user_model.username == user_data.username
                )
            )
            user = result.scalars().first()
            if not user or not verify_password(user_data.password, user.hashed_password):
                return {"error": "Invalid credentials"}, 401
            
            token = create_access_token(data={"sub": user.username})
            return {"access_token": token, "token_type": "bearer"}

    def register_admin_routes(self, app, path="/admin/{item_id:int}/make-admin"):
        """Register admin management endpoints."""
        admin_dep = self.admin_only()

        @app.route(path, methods=["POST"])
        async def make_admin(
            item_id: int, 
            db: AsyncSession, 
            admin_user: Any = Depends(admin_dep)
        ):
            target_user = await db.get(self.user_model, int(item_id))
            if not target_user:
                return JsonResponse({"error": "User not found"}, status_code=404)

            # DYNAMIC UPDATE: Use the detected admin field
            setattr(target_user, self.admin_field, True)

            # Capture scalar BEFORE commit
            target_user_id = int(target_user.id)

            await db.commit()

            return JsonResponse(
                {"message": "User promoted to admin", "user_id": target_user_id},
                status_code=200
            )

    # ========================================================================
    # HELPERS
    # ========================================================================

    async def ensure_admin(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        email: str = "admin@site.com",
    ):
        """
        Creates or updates an admin user using the detected admin field.
        """
        result = await db.execute(
            select(self.user_model).where(self.user_model.username == username)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            # Check the detected field specifically
            if not getattr(existing, self.admin_field, False):
                setattr(existing, self.admin_field, True)
                await db.commit()
            return existing

        # Create new user with dynamic kwargs
        user_data = {
            "username": username,
            "hashed_password": get_password_hash(password),
            "email": email,
            self.admin_field: True, # <--- Sets 'is_admin' or 'is_superuser' correctly
        }
        
        # Wrap in try/except in case ensure_admin is called but user exists with different email/params
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
