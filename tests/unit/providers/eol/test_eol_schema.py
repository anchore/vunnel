import pytest
from datetime import datetime

from vunnel.schema.eol import EOLSchema


def test_schema_validation():
    schema = EOLSchema()
    
    # Test valid data with CPE identifiers
    valid_data = {
        "product": "python",
        "cycle": "3.12",
        "identifiers": [
            {"type": "cpe", "id": "cpe:/:a:python:python"},
            {"type": "cpe", "id": "cpe:2.3:a:python:python"}
        ]
    }
    schema.validate(valid_data)  # Should not raise any exception

    # Test invalid identifier type
    invalid_type_data = {
        "product": "python",
        "cycle": "3.12",
        "identifiers": [
            {"type": 123, "id": "cpe:/:a:python:python"}  # type should be string
        ]
    }
    with pytest.raises(ValueError, match="identifier type and id must be strings"):
        schema.validate(invalid_type_data)

    # Test missing identifier fields
    missing_fields_data = {
        "product": "python",
        "cycle": "3.12",
        "identifiers": [
            {"type": "cpe"}  # missing id field
        ]
    }
    with pytest.raises(ValueError, match="identifier must have 'type' and 'id' fields"):
        schema.validate(missing_fields_data)

    # Test invalid identifier structure
    invalid_structure_data = {
        "product": "python",
        "cycle": "3.12",
        "identifiers": "not a list"  # should be a list
    }
    with pytest.raises(ValueError, match="identifiers must be of type list"):
        schema.validate(invalid_structure_data) 