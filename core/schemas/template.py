from typing import ClassVar

from pydantic import BaseModel

from core import database_arango

#TODO: Import Jinja functions to render templates

class Template(BaseModel, database_arango.ArangoYetiConnector):
    """A template for exporting data to an external system."""
    _collection_name: ClassVar[str] = 'templates'

    id: str | None = None
    name: str
    template: str

    @classmethod
    def load(cls, object: dict) -> "Template":
        return cls(**object)

    def render(self, data: list["Observable"], output_file: str) -> None:
        """Renders the template with the given data to the output file."""
        #TODO: Change this to an actual render function
        with open(output_file, 'w+') as fd:
            for d in data:
                fd.write(f'{d.value}\n')

    def render_raw(self, data: list["Observable"]) -> str:
        """Renders the template with the given data to a string."""
        return '\n'.join([d.value for d in data])
