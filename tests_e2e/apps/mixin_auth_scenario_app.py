"""Scenario app: the documented, intended usage pattern --
`class User(JetioAuthMixin, JetioModel)` -- used for real, not worked
around. Before both fixes (this repo's mixins.py fix + jetio's
API-config-MRO fix), this either crashed at class-definition time or, once
that crash was fixed, silently leaked hashed_password on every read.
"""

import os

from jetio import Jetio, CrudRouter, JetioModel, add_swagger_ui, Base, engine, SessionLocal
from jetio_auth import AuthRouter, JetioAuthMixin
from sqlalchemy.orm import Mapped, mapped_column


class User(JetioAuthMixin, JetioModel):
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str]


app = Jetio(title="Mixin auth scenario")
add_swagger_ui(app)

auth = AuthRouter(User, company_name="Mixin Scenario")
auth.register_routes(app)  # POST /register, POST /login
auth.register_admin_routes(app)  # POST /admin/{id}/make-admin

CrudRouter(
    model=User,
    exclude_methods=["POST", "PUT", "DELETE"],
    secure=True,
    policy={"GET": auth.owner_or_admin(User, audit_fields=["id"])},
).register_routes(app)


@app.on_event("startup")
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        await auth.ensure_admin(db, username="admin", password="scenario-admin-pw", email="admin@scenario.local")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ["JETIO_APP_PORT"]))
