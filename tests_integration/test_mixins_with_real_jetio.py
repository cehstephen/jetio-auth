"""JetioAuthMixin (and friends) combined with the real JetioModel -- see
this directory's README for why these can't live under tests/, which
mocks jetio entirely.

Bug being guarded against: jetio_auth/mixins.py used
`from __future__ import annotations`, which makes every annotation in
that module an unevaluated string at class-definition time (e.g. the
literal string "Mapped[bool]" rather than the real typing object).
JetioModel's ModelMetaclass collects annotations from the whole MRO
without re-resolving those strings, so it tried to build a Pydantic field
named "Mapped[bool]Read" and crashed with:

    SyntaxError: Forward reference must be an expression -- got 'Mapped[bool]Read'

Reproduced with jetio 1.2.2 / jetio-auth (pre-fix). The mixins module also
used `datetime | None` / `str | None` PEP 604 union syntax on
JetioEmailConfirmationMixin and JetioPasswordResetMixin's columns -- those
require `from __future__ import annotations` on Python < 3.10 (setup.cfg
declares python_requires >= 3.8), so simply deleting the import would trade
this crash for a TypeError on 3.8/3.9 evaluating `datetime | None` at
class-body execution time. The fix replaces that syntax with
`Optional[datetime]`/`Optional[str]` instead of just removing the import.
"""

import pytest
from jetio import JetioModel
from jetio_auth.mixins import JetioAuthMixin, JetioFullAuthMixin
from sqlalchemy.orm import Mapped, mapped_column


def test_auth_mixin_combines_with_real_jetio_model():
    class MixinUser(JetioAuthMixin, JetioModel):
        username: Mapped[str] = mapped_column(unique=True)
        email: Mapped[str]

    # The crash happened during class creation (ModelMetaclass.__init__),
    # so merely reaching this line without a SyntaxError is the real
    # assertion -- this is the part this repo's own fix (mixins.py) is
    # responsible for, and is independent of the jetio-side fix below.
    assert hasattr(MixinUser, "__pydantic_read_model__")
    assert hasattr(MixinUser, "__pydantic_create_model__")

    create_fields = MixinUser.__pydantic_create_model__.model_fields
    assert "is_admin" not in create_fields, "server_default field should be dropped from create schema"
    assert "hashed_password" not in create_fields, "name-matched server-side field"

    read_fields = MixinUser.__pydantic_read_model__.model_fields
    assert "is_admin" in read_fields


@pytest.mark.xfail(
    reason=(
        "Depends on a separate fix in the jetio repo, not this one: "
        "https://github.com/cehstephen/jetio/pull/4 (ModelMetaclass resolving "
        "`class API` via the MRO). Passes once that's merged and this "
        "package's jetio dependency is bumped past it; until then, this "
        "documents the gap rather than silently hiding it."
    ),
    strict=False,
)
def test_hashed_password_is_excluded_from_read_via_the_mixins_api():
    class MixinUserForExclusionCheck(JetioAuthMixin, JetioModel):
        username: Mapped[str] = mapped_column(unique=True)
        email: Mapped[str]

    read_fields = MixinUserForExclusionCheck.__pydantic_read_model__.model_fields
    assert "hashed_password" not in read_fields, "exclude_from_read should still hide this"


def test_full_auth_mixin_combines_with_real_jetio_model():
    # Exercises the Optional[datetime]/Optional[str] columns specifically
    # (email confirmation + password reset fields), not just the base
    # is_admin/hashed_password pair.
    class FullMixinUser(JetioFullAuthMixin, JetioModel):
        username: Mapped[str] = mapped_column(unique=True)
        email: Mapped[str]

    read_fields = FullMixinUser.__pydantic_read_model__.model_fields
    assert "email_confirmed" in read_fields
    assert "email_confirmed_at" in read_fields
    assert "password_reset_token_hash" in read_fields
