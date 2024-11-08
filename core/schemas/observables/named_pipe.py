from typing import Literal

from core.schemas import observable


class NamedPipe(observable.Observable):
    type: Literal["named_pipe"] = "named_pipe"
