from core.schemas.observable import Observable
from core.schemas.observable import ObservableType


class CommandLine(Observable):
    value: str
    type: ObservableType = ObservableType.command_line
