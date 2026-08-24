"""Real-life scenario against a real running app (see
apps/mixin_auth_scenario_app.py) using JetioAuthMixin exactly as
documented -- `class User(JetioAuthMixin, JetioModel)`. Complements
tests_integration/test_mixins_with_real_jetio.py (which checks the
generated Pydantic schema in-process) with real subprocess + real HTTP:
actual registration, actual login, actual JWT, actual wire-level response
bytes.

Needs a sibling jetio checkout with the API-config-MRO fix -- see
conftest.py's docstring. Skips (doesn't fail) if that checkout isn't
found, since it's an external dependency this repo alone can't guarantee.
"""

import httpx


def _register(base_url, username, password, **extra):
    payload = {"username": username, "email": f"{username}@example.com", "password": password, **extra}
    return httpx.post(f"{base_url}/register", json=payload)


def _login(base_url, username, password):
    return httpx.post(f"{base_url}/login", json={"username": username, "password": password})


class TestDocumentedUsagePatternWorksEndToEnd:
    """This is the whole point of both fixes combined: the pattern
    JetioAuthMixin's own docstring shows -- `class User(JetioAuthMixin,
    JetioModel)` -- should just work, with no workaround needed."""

    def test_app_with_the_mixin_starts_and_serves_requests(self, auth_app):
        # Reaching this point at all is already the crash-fix proof --
        # tests_integration/ proves the class definition doesn't crash;
        # this proves a whole app built on it actually boots and serves.
        resp = httpx.get(f"{auth_app}/docs")
        assert resp.status_code == 200

    def test_full_register_login_read_flow(self, auth_app):
        reg = _register(auth_app, "alice", "correct-horse")
        assert reg.status_code == 201

        login = _login(auth_app, "alice", "correct-horse")
        assert login.status_code == 200
        token = login.json()["access_token"]

        me = httpx.get(f"{auth_app}/users/2", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["username"] == "alice"

    def test_unauthenticated_read_is_rejected(self, auth_app):
        _register(auth_app, "bob", "pw")
        resp = httpx.get(f"{auth_app}/users/2")
        assert resp.status_code == 401


class TestMixinsSecurityPropertiesHoldOverRealHttp:
    def test_hashed_password_never_appears_in_a_real_response_body(self, auth_app):
        _register(auth_app, "carol", "hunter2")
        token = _login(auth_app, "carol", "hunter2").json()["access_token"]

        resp = httpx.get(f"{auth_app}/users/2", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "hashed_password" not in resp.text
        assert "hunter2" not in resp.text

    def test_is_admin_injection_at_registration_is_silently_ignored(self, auth_app):
        # is_admin has a server-side default (JetioAuthMixin), so Jetio's
        # schema generator drops it from AuthRouter's registration schema
        # entirely -- verified here as an actual request, not a schema check.
        _register(auth_app, "dave", "pw", is_admin=True)
        token = _login(auth_app, "dave", "pw").json()["access_token"]

        me = httpx.get(f"{auth_app}/users/2", headers={"Authorization": f"Bearer {token}"})
        assert me.json()["is_admin"] is False


class TestAdminFlowWorksWithTheMixinToo:
    def test_bootstrapped_admin_can_promote_a_mixin_based_user(self, auth_app):
        _register(auth_app, "erin", "pw")
        admin_token = _login(auth_app, "admin", "scenario-admin-pw").json()["access_token"]
        erin_token = _login(auth_app, "erin", "pw").json()["access_token"]

        self_promote = httpx.post(
            f"{auth_app}/admin/2/make-admin", headers={"Authorization": f"Bearer {erin_token}"}
        )
        assert self_promote.status_code == 403

        promote = httpx.post(
            f"{auth_app}/admin/2/make-admin", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert promote.status_code == 200

        refreshed = _login(auth_app, "erin", "pw").json()["access_token"]
        erin = httpx.get(f"{auth_app}/users/2", headers={"Authorization": f"Bearer {refreshed}"})
        assert erin.json()["is_admin"] is True
