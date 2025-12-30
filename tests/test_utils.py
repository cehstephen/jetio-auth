import pytest
from pydantic import BaseModel
from jetio_auth.utils import create_register_schema
from .conftest import User

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
