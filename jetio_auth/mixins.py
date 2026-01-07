# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

"""
Authentication mixins for Jetio models.

This module provides a set of composable SQLAlchemy mixins that define the database
schema "contracts" required by `AuthRouter`.

Design goals
------------
- **Composable schema**: Each mixin adds only the columns it claims to add.
- **Safe defaults**: Security-critical flags default at both Python and DB levels.
- **Framework-friendly**: No assumptions about identity fields (`username`, `email`, etc.).
- **Production-ready flexibility**: Support password auth, email confirmation, and password reset
  as independent capabilities.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import expression

class JetioAuthMixin:
    """
    Core authentication mixin (password auth + admin flag).
    """

    is_admin: Mapped[bool] = mapped_column(
        default=False,
        server_default=expression.false(),
        doc="Designates that this user has administrative privileges.",
    )

    hashed_password: Mapped[str] = mapped_column(
        nullable=False,
        doc="The bcrypt hash of the user's password.",
    )

    class API:
        exclude_from_read = ["hashed_password"]


class JetioEmailConfirmationMixin:
    email_confirmed: Mapped[bool] = mapped_column(
        default=False,
        server_default=expression.false(),
    )

    email_confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    email_confirmation_token_hash: Mapped[str | None] = mapped_column(nullable=True)

    email_confirmation_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)


class JetioPasswordResetMixin:
    password_reset_token_hash: Mapped[str | None] = mapped_column(nullable=True)

    password_reset_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)


class JetioAuthWithResetMixin(JetioAuthMixin, JetioPasswordResetMixin):
    pass


class JetioFullAuthMixin(JetioAuthMixin, JetioEmailConfirmationMixin, JetioPasswordResetMixin):
    pass
