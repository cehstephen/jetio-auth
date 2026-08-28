"""Real-life scenario against a real running app (see
apps/custom_admin_field_scenario_app.py) proving GH issue #6 is closed:
AuthRouter configured with a custom-named admin field ("promoted") must
not let self-registration set that field, over real HTTP -- not just in
the generated Pydantic schema (see tests/test_auth_router.py for that
check in isolation).
"""

import httpx


def _register(base_url, username, password, **extra):
    payload = {"username": username, "email": f"{username}@example.com", "password": password, **extra}
    return httpx.post(f"{base_url}/register", json=payload)


def _login(base_url, username, password):
    return httpx.post(f"{base_url}/login", json={"username": username, "password": password})


class TestAdminOnlyRespectsTheCustomAdminField:
    """The 403 in TestCustomAdminFieldCannotBeSelfRegistered's first test,
    on its own, doesn't prove admin_only() is actually checking the right
    field -- it could just as well be rejecting everyone unconditionally
    (which is exactly what it did before admin_only()/owner_or_admin()
    were fixed to use self.admin_field instead of a hardcoded "is_admin").
    This proves the positive case: a legitimately-promoted user (see the
    scenario app's ensure_admin() call at startup) DOES pass."""

    def test_legitimately_promoted_user_passes(self, custom_admin_field_app):
        login = _login(custom_admin_field_app, "legit_admin", "admin-pw")
        assert login.status_code == 200
        token = login.json()["access_token"]

        check = httpx.get(
            f"{custom_admin_field_app}/admin-only-check",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert check.status_code == 200


class TestCustomAdminFieldCannotBeSelfRegistered:
    def test_registering_with_the_admin_field_set_does_not_grant_it(self, custom_admin_field_app):
        reg = _register(custom_admin_field_app, "attacker", "correct-horse", promoted=True)
        assert reg.status_code == 201

        login = _login(custom_admin_field_app, "attacker", "correct-horse")
        token = login.json()["access_token"]

        # The real proof: the self-registered account cannot pass an
        # admin_only() check, regardless of what the /register payload
        # claimed. Before the fix, "promoted" reached the User constructor
        # directly and this would return 200.
        check = httpx.get(
            f"{custom_admin_field_app}/admin-only-check",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert check.status_code == 403

    def test_normal_registration_without_the_admin_field_still_works(self, custom_admin_field_app):
        reg = _register(custom_admin_field_app, "regular_user", "correct-horse")
        assert reg.status_code == 201

        login = _login(custom_admin_field_app, "regular_user", "correct-horse")
        assert login.status_code == 200
        assert "access_token" in login.json()
