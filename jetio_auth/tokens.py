# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

"""
Token utilities for jetio-auth.

This module provides:
- Secure token generation (URL-safe)
- SHA-256 hashing (hex)
- UTC-aware timestamps
- Expiry helpers

Design goals:
- No framework dependencies
- Safe-by-default (store only hashed tokens in DB)
- Easy to unit test
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional


def utcnow() -> datetime:
    """
    Returns a timezone-aware UTC datetime.

    Using timezone-aware timestamps prevents subtle bugs when comparing naive datetimes.
    """
    return datetime.now(timezone.utc)


def generate_token(nbytes: int = 32) -> str:
    """
    Generates a URL-safe random token.

    Args:
        nbytes: Approximate entropy in bytes (default: 32 ~ 256 bits).
                Note: token_urlsafe returns a string longer than nbytes.

    Returns:
        A URL-safe token string suitable for use in links.
    """
    if nbytes < 16:
        # 128-bit minimum to avoid weak tokens
        raise ValueError("nbytes must be >= 16")
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    """
    Computes SHA-256 hash of the input string and returns hex digest.

    Store this output in the database instead of the raw token.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("value must be a non-empty string")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def expires_in_minutes(minutes: int) -> datetime:
    """
    Returns a UTC datetime representing now + minutes.

    Args:
        minutes: Positive integer number of minutes.

    Returns:
        Expiry timestamp (UTC, timezone-aware).
    """
    if minutes <= 0:
        raise ValueError("minutes must be > 0")
    return utcnow() + timedelta(minutes=minutes)


def is_expired(expires_at: Optional[datetime]) -> bool:
    """
    Checks whether a given expiry timestamp has expired.

    Fail-closed behavior:
      - If expires_at is None -> treated as expired.

    Args:
        expires_at: A timezone-aware datetime (recommended) or None.

    Returns:
        True if expired (or missing), False otherwise.
    """
    if expires_at is None:
        return True

    # If a naive datetime is passed, assume it's UTC to avoid crashes,
    # but prefer storing timezone-aware datetimes.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return utcnow() > expires_at
