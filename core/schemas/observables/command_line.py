from typing import Literal

from core.schemas import observable


class CommandLine(observable.Observable):
    type: Literal["command_line"] = "command_line"
