# Jetio Auth 🔐

**Seamless, zero-config authentication for the [Jetio](https://jetio.org) framework.**

`jetio-auth` is a battery-included authentication plugin designed to get your application secured in minutes. It bridges your SQLAlchemy database models directly to your API, handling password hashing, JWT token issuance, and granular permission policies automatically.

---

### ✨ Key Features

* **🧠 Intelligent Auto-Discovery:** Automatically detects your admin flags (`is_admin`, `is_superuser`, etc.). No configuration required.
* **🏗️ Dynamic Schema Generation:** Inspects your SQLAlchemy User model and instantly generates a Pydantic validation schema for registration. (Adds `age`, `phone`, etc., to the API automatically!)
* **🛡️ Secure by Default:**
    * Built-in **Bcrypt** password hashing.
    * **Mass Assignment Protection** (prevents users from registering as admins).
    * Standardized **JWT** (JSON Web Token) flow.
* **🔌 Drop-in Mixins:** Provides a `JetioAuthMixin` to equip your models with auth columns instantly.

---

### 📦 Installation

```bash
pip install jetio-auth 
```


🚀 Quick Start
1. Define your User Model

Inherit from JetioAuthMixin to get hashed_password and is_admin columns automatically.


```python 
# models.py
from jetio import JetioModel
from jetio_auth.mixins import JetioAuthMixin
from sqlalchemy.orm import Mapped, mapped_column

class User(JetioModel, JetioAuthMixin):
    # You define the identity fields (username/email)
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str] = mapped_column(unique=True)
    age: Mapped[int] = mapped_column(default=18)
```

2. Initialize the Auth Router

In your main application file:
```python
# app.py
from jetio_auth import AuthRouter
from models import User

# Initialize the router with your model
# The plugin automatically detects 'is_admin' and builds the schemas.
auth = AuthRouter(user_model=User)

# Register endpoints (/login, /register)
auth.register_routes(app)

# Register admin management endpoints (/admin/{id}/make-admin)
auth.register_admin_routes(app)
```

3. Protect your Routes

Use the provided policies to secure your data.
```python 
from jetio import CrudRouter

# Example: A router where only the Owner (or an Admin) can edit/delete
CrudRouter(
    model=Post,
    secure=True,
    auth_dependency=auth.get_auth_dependency(), # Validates JWT
    policy={        
        "POST": auth.get_auth_dependency(), # Any logged-in user
         "PUT": auth.owner_or_admin(Post), # only the owner or admin can edit a post
         "DELETE": auth.admin_only() # Only admins can delete. You can alternatively use owner_or_admin(Post), this is for demo only.
    }
).register_routes(app)
```

🛠️ Utilities
Creating the First Admin

Since the API protects against self-promotion, use the ensure_admin helper in your startup script.

```python
async def init_db():
    async with AsyncSession(engine) as session:
        # Idempotent: safe to run on every startup
        await auth.ensure_admin(
            db=session,
            username="admin",
            password="securePassword123",
            email="admin@jetio.org"
        )
```

Manual Admin Promotion

If you are already an admin, you can promote other users via the API:
```bash 
POST /admin/5/make-admin
Authorization: Bearer <your-admin-token>
```

⚙️ How it works
The "Single Source of Truth"

jetio-auth doesn't force you to use a specific column name for permissions. It scans your model for standard flags in this order:

    is_admin

    is_superuser

    is_staff

    is_master

Whichever it finds first, it locks onto as the authority for admin_only policies.
Dynamic Validation

When a user hits /register, the plugin doesn't just look for username/password. It looks at your User table columns:

    age: int → API requires an Integer (or Optional if default exists).

    bio: str → API accepts a String.

    is_admin → Excluded automatically for security.
