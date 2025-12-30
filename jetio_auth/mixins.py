# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

"""
Standard authentication mixins for Jetio models.

This module provides the `JetioAuthMixin`, a "batteries-included" helper class designed
to streamline the integration of authentication into Jetio applications. By inheriting
from this mixin, developers ensure their user models strictly adhere to the structural
contracts required by the `AuthRouter`.

Key Features:
- **Zero-Config Security**: Automatically adds password hash storage and admin flags.
- **Safe Defaults**: Enforces database-level defaults and prevents accidental hash leakage via API.
- **Modern Typing**: Uses SQLAlchemy 2.0 `Mapped` types for perfect IDE support and OpenAPI generation.

Usage:
    >>> from jetio import JetioModel
    >>> from jetio_auth.mixins import JetioAuthMixin
    >>>
    >>> class User(JetioModel, JetioAuthMixin):
    ...     username: Mapped[str] = mapped_column(unique=True)
    ...     # 'hashed_password' and 'is_admin' are added automatically!
"""

from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import expression

class JetioAuthMixin:
    """
    A plug-and-play Mixin that equips a Jetio Model with essential authentication columns.

    This mixin provides the necessary schema contract for `AuthRouter` to function
    without manual configuration. It purposefully omits identity fields (like `username`
    or `email`) to give developers full flexibility in defining their login strategy.

    Columns Added:
        is_admin (bool):
            A flag used by `admin_only` policies to authorize high-privilege actions.
            Defaults to False at both the Python and Database level.
        
        hashed_password (str):
            Stores the bcrypt hash of the user's password. Marked as non-nullable
            to enforce security integrity.

    Safety Features:
        - Includes an internal `API` configuration class that automatically adds
          `hashed_password` to `exclude_from_read`. This ensures password hashes
          are never serialized into JSON responses by default.
    """
    
    # -----------------------------------------------------------------------
    # 1. Authorization Flags
    # -----------------------------------------------------------------------
    
    # The administrative privilege flag.
    # We use `server_default=expression.false()` to ensure data integrity at the 
    # database level, preventing NULL states for critical permission logic.
    is_admin: Mapped[bool] = mapped_column(
        default=False, 
        server_default=expression.false(),
        doc="Designates that this user has administrative privileges."
    )

    # -----------------------------------------------------------------------
    # 2. Credential Storage
    # -----------------------------------------------------------------------

    # The password hash storage.
    # We enforce `nullable=False` because a user record without a password is 
    # invalid in a password-based auth system.
    hashed_password: Mapped[str] = mapped_column(
        nullable=False,
        doc="The bcrypt hash of the user's password."
    )

    # -----------------------------------------------------------------------
    # 3. API Security Configuration
    # -----------------------------------------------------------------------

    class API:
        """
        Internal Jetio configuration hook.
        
        This instructs the Jetio serializer to exclude specific sensitive fields
        from public API responses (GET requests).
        
        Warning:
            If your subclass defines its own `class API`, it will override this
            configuration entirely. You must manually re-add "hashed_password"
            to your `exclude_from_read` list in that case.
        """
        exclude_from_read = ["hashed_password"]
