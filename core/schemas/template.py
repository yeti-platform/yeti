import os
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import jinja2
from pydantic import BaseModel

from core.config.config import yeti_config

if TYPE_CHECKING:
    from core.schemas.observable import Observable


class Template(BaseModel):
    """A template for exporting data to an external system."""

    name: str
    template: str

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

    def save(self) -> "Template":
        directory = Path(yeti_config.get("system", "template_dir", "/opt/yeti/templates"))
        file = directory / f'{self.name}.jinja2'
        file.write_text(self.template)
        return self

    @classmethod
    def find(cls, name: str) -> Optional["Template"]:
        directory = Path(yeti_config.get("system", "template_dir", "/opt/yeti/templates"))
        file = directory / f'{name}.jinja2'
        if file.exists():
            return Template(name=name, template=file.read_text())
        return None
