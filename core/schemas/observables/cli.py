from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
class CLI(Observable):
    value: str
    type: ObservableType = ObservableType.cli
