from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal

class CommandLine(Observable):
    value: str
    type: Literal['cli'] = ObservableType.command_line
