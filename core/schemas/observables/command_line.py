from typing import Literal

from core.schemas import observable


class CommandLine(observable.Observable):
    value: str
    type: Literal[observable.ObservableType.command_line] = observable.ObservableType.command_line


observable.TYPE_MAPPING[observable.ObservableType.command_line] = CommandLine
