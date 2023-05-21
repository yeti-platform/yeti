from pydantic import BaseModel

from core import database_arango


class Template(BaseModel, database_arango.ArangoYetiConnector):
    """A template for exporting data to an external system."""
    _collection_name = 'templates'

    id: str | None
    name: str
    template: str

    @classmethod
    def load(cls, object: dict) -> "Template":
        return cls(**object)
