
from core.schemas.observable import Observable,ObservableType


class Ssdeep_Observable(Observable):
    value: str
    type: str = ObservableType.ssdeep