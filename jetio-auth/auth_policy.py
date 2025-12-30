# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Website: https://jetio.org
#
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# 
# This source code is licensed under the BSD 3-Clause license found in the
# LICENSE file in the root directory of this source tree.
#
# Author:   Stephen Burabari Tete
# Contact:  cehtete [at] gmail.com
# LinkedIn: https://www.linkedin.com/in/tete-stephen/ 
# ---------------------------------------------------------------------------

from typing import Optional, List, Any
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.exceptions import HTTPException

from jetio.auth import decode_access_token
from jetio.security import require_audit_field


class AuthPolicy:
    """
    Internal authorization policy handler for AuthRouter.
    
    This class is not meant to be used directly by end users.
    Instead, use AuthRouter which delegates to this class internally.
    
    Provides:
    - JWT token validation
    - Ownership verification
    - Admin-only access control
    """
    
    def __init__(self, user_model, admin_field: str = "is_admin"):
        self.user_model = user_model
        self.admin_field = admin_field

    def get_auth_dependency(self):
        """
        Dependency that validates JWT token and returns the authenticated user.
        
        Returns a dependency function that can be used with Jetio's Depends().
        """
        async def dependency(request: Request, db: AsyncSession):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)
            if not payload:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            result = await db.execute(
                select(self.user_model).where(
                    self.user_model.username == payload.get("sub")
                )
            )
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            return user
        
        return dependency

    def owner_or_admin(
        self,
        resource_model,
        audit_fields: Optional[List[str]] = None,
    ):
        """
        Policy that ensures requester is the resource owner OR an admin.

        Uses Jetio's centralized ownership resolver (security.py):
        - Determines the ownership column once (e.g. author_id, user_id).
        - FAIL-CLOSED if the model has no recognized ownership field.
        - FAIL-CLOSED for PUT/DELETE if item_id isn't injected.
        
        Args:
            resource_model: The SQLAlchemy model to check ownership against
            audit_fields: Optional list of field names to check for ownership
                         (e.g., ['author_id', 'user_id', 'created_by'])
        
        Returns:
            A dependency function that performs authentication and authorization
        """
        # Resolve once, fail-closed if not present
        resolved_owner_field = require_audit_field(resource_model, audit_fields=audit_fields)

        async def dependency(
            request: Any, 
            db: AsyncSession, 
            item_id: Optional[int] = None
        ):
            # 1) Authenticate - get the current user
            user = await self.get_auth_dependency()(request, db)

            # 2) FAIL-CLOSED: modifying operations require item_id
            if request.method in ("PUT", "DELETE") and item_id is None:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Security misconfiguration: item_id not injected into dependency. "
                        "Ensure Jetio Depends() resolver passes path params to dependencies."
                    ),
                )

            # If no item_id (e.g. POST creating new resource), ownership check doesn't apply
            # The authenticated user will become the owner
            if item_id is None:
                return user

            # 3) Load the resource from database
            result = await db.execute(
                select(resource_model).where(resource_model.id == int(item_id))
            )
            item = result.scalar_one_or_none()
            if not item:
                raise HTTPException(status_code=404, detail="Resource not found")

            # 4) Perform owner/admin authorization check
            is_admin = bool(getattr(user, "is_admin", False))

            try:
                current_user_id = int(getattr(user, "id"))
                record_owner_id = int(getattr(item, resolved_owner_field))
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=500, 
                    detail="System Error: ID type mismatch"
                )

            # Allow access if user is admin OR owns the resource
            if is_admin or (current_user_id == record_owner_id):
                return user

            # Deny access - user is neither admin nor owner
            raise HTTPException(status_code=403, detail="Forbidden")

        return dependency

    def admin_only(self):
        """
        Policy that restricts access to admin users only.
        
        Returns:
            A dependency function that only allows admin users
        """
        async def dependency(request: Request, db: AsyncSession):
            user = await self.get_auth_dependency()(request, db)
            if getattr(user, "is_admin", False):
                return user
            raise HTTPException(
                status_code=403, 
                detail="Forbidden: Admin access required."
            )
        
        return dependency
