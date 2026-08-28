import pytest
from pydantic import BaseModel
from jetio_auth.utils import create_register_schema
from .conftest import User, CustomAdminFieldUser

def test_create_register_schema_structure():
    """Ensure schema generation correctly maps included and excluded fields."""
    Schema = create_register_schema(User)
    
    assert issubclass(Schema, BaseModel)
    fields = Schema.model_fields
    
    # Verify Included Fields
    assert "username" in fields
    assert "age" in fields
    assert "password" in fields  # Injected raw password field
    
    # Verify Excluded Security Fields
    assert "id" not in fields
    assert "hashed_password" not in fields
    assert "is_admin" not in fields

def test_optional_fields_logic():
    """Ensure fields with database defaults are marked as optional in the schema."""
    Schema = create_register_schema(User)
    
    # 'age' has a default (18), so it must NOT be required
    assert Schema.model_fields["age"].is_required() is False 
    
    # 'username' is mandatory (unique/not-null), so it MUST be required
    assert Schema.model_fields["username"].is_required() is True


def test_custom_admin_field_is_not_excluded_by_default():
    """EXCLUDED_FIELDS only guards a fixed set of conventional names
    (is_admin/is_superuser/is_staff) -- a custom-named admin field is NOT
    protected by the base call alone. See GH issue #6: this is exactly
    why AuthRouter must pass its resolved admin_field through
    extra_excluded_fields (next test) rather than relying on this."""
    Schema = create_register_schema(CustomAdminFieldUser)
    assert "promoted" in Schema.model_fields


def test_extra_excluded_fields_protects_a_custom_admin_field():
    Schema = create_register_schema(CustomAdminFieldUser, extra_excluded_fields={"promoted"})
    assert "promoted" not in Schema.model_fields
    # Unrelated fields are unaffected.
    assert "username" in Schema.model_fields
