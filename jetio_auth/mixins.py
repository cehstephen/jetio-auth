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

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import expression

# No `from __future__ import annotations` here, deliberately: it makes every
# annotation in this module an unevaluated string at class-definition time
# (e.g. the literal string "Mapped[bool]" rather than the real typing
# object). JetioModel's ModelMetaclass collects annotations from the whole
# MRO without re-resolving those strings, so combining one of these mixins
# with JetioModel crashed with
# `SyntaxError: Forward reference must be an expression -- got 'Mapped[bool]Read'`.
# Optional[...] is used below instead of the `X | None` PEP 604 syntax for
# the same reason `X | None` needed the future import in the first place:
# without it, `datetime | None` fails at class-body evaluation time on
# Python < 3.10 (this package declares python_requires >= 3.8).

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

    email_confirmed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    email_confirmation_token_hash: Mapped[Optional[str]] = mapped_column(nullable=True)

    email_confirmation_expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)


class JetioPasswordResetMixin:
    password_reset_token_hash: Mapped[Optional[str]] = mapped_column(nullable=True)

    password_reset_expires_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)


class JetioAuthWithResetMixin(JetioAuthMixin, JetioPasswordResetMixin):
    pass


class JetioFullAuthMixin(JetioAuthMixin, JetioEmailConfirmationMixin, JetioPasswordResetMixin):
    pass
