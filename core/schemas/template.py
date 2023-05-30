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

    def render(self, data: list["Observable"], output_file: str) -> None:
        """Renders the template with the given data to the output file."""
        #TODO: Change this to an actual render function
        with open(output_file, 'w+') as fd:
            for d in data:
                fd.write(f'{d.value}\n')
