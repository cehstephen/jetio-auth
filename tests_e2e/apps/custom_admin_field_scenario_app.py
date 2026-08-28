"""Scenario app: AuthRouter configured with a custom-named admin field
("promoted" instead of the conventional "is_admin") -- the exact
configuration proven vulnerable in GH issue #6. Before the
create_register_schema(extra_excluded_fields=...) fix, "promoted" was
absent from EXCLUDED_FIELDS' fixed guess-list and so was accepted as a
plain client-settable field on POST /register.
"""

import os

from jetio import Jetio, JetioModel, add_swagger_ui, Base, engine, SessionLocal, Request, JsonResponse, Depends
from jetio_auth import AuthRouter
from sqlalchemy.orm import Mapped, mapped_column


class User(JetioModel):
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str]
    hashed_password: Mapped[str]
    promoted: Mapped[bool] = mapped_column(default=False)


app = Jetio(title="Custom admin field scenario")
add_swagger_ui(app)

auth = AuthRouter(User, admin_field="promoted", company_name="Custom Admin Field Scenario")
auth.register_routes(app)  # POST /register, POST /login
auth.register_admin_routes(app)  # POST /admin/{id}/make-admin


@app.route("/admin-only-check", methods=["GET"])
async def admin_only_check(request: Request, user=Depends(auth.admin_only())):
    return JsonResponse({"ok": True})


@app.on_event("startup")
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        # A legitimately-promoted user, via the real promotion path (sets
        # "promoted" directly server-side) -- the positive-case proof that
        # admin_only() actually recognizes this custom-named admin field,
        # not just that it happens to reject everyone.
        await auth.ensure_admin(db, username="legit_admin", password="admin-pw", email="admin@scenario.local")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ["JETIO_APP_PORT"]))
