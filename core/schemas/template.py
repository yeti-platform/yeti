import os
from typing import TYPE_CHECKING, ClassVar

import jinja2

from core import database_arango
from core.schemas.model import YetiModel

if TYPE_CHECKING:
    from core.schemas.observable import Observable

# TODO: Import Jinja functions to render templates


class Template(YetiModel, database_arango.ArangoYetiConnector):
    """A template for exporting data to an external system."""

    _collection_name: ClassVar[str] = "templates"

    name: str
    template: str

    @classmethod
    def load(cls, object: dict) -> "Template":
        return cls(**object)

    def render(self, data: list["Observable"], output_file: str | None) -> None | str:
        """Renders the template with the given data to the output file."""

        environment = jinja2.Environment()
        template = environment.from_string(self.template)
        result = template.render(data=data)
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w+") as fd:
                fd.write(result)
            return None
        else:
            return result
