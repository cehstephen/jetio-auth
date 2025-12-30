# ---------------------------------------------------------------------------
# Jetio Auth Plugin
# Copyright (c) 2025 Stephen Burabari Tete. All Rights Reserved.
# Licensed under the BSD 3-Clause license.
#
# LinkedIn: https://www.linkedin.com/in/tete-stephen/
# ---------------------------------------------------------------------------

"""
Utilities for dynamic Pydantic schema generation.
"""

from typing import Type, Any, Optional, Dict, Tuple
from pydantic import create_model, BaseModel
from sqlalchemy.inspection import inspect
from sqlalchemy.sql import sqltypes

# Map SQLAlchemy types to Python natives
TYPE_MAPPING = {
    sqltypes.Integer: int,
    sqltypes.String: str,
    sqltypes.Boolean: bool,
    sqltypes.Float: float,
    sqltypes.Date: str,
    sqltypes.DateTime: str,
}

EXCLUDED_FIELDS = {
    "id", 
    "hashed_password", 
    "created_at", 
    "updated_at", 
    "is_admin", 
    "is_superuser",
    "is_staff"
}

def create_register_schema(model_class: Type[Any]) -> Type[BaseModel]:
    """
    Generates a Pydantic model for user registration based on a SQLAlchemy model.
    """
    mapper = inspect(model_class)
    fields: Dict[str, Tuple[type, Any]] = {}

    for column in mapper.columns:
        if column.name in EXCLUDED_FIELDS:
            continue
            
        # 1. Resolve Python type
        python_type = str 
        for sql_type, py_type in TYPE_MAPPING.items():
            if isinstance(column.type, sql_type):
                python_type = py_type
                break
        
        # 2. Check for defaults (The Logic Fix)
        # If the column has a default value (e.g. default=18), the API input
        # should be optional, even if the database column is Not Null.
        has_default = (column.default is not None) or (column.server_default is not None)
        
        # 3. Handle Optionality
        if column.nullable or has_default:
            fields[column.name] = (Optional[python_type], None)
        else:
            fields[column.name] = (python_type, ...)

    # Inject raw password field
    fields["password"] = (str, ...)

    return create_model(
        f"{model_class.__name__}Register",
        **fields
    )
