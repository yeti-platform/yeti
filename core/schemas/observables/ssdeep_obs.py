
from core.schemas.observable import Observable,ObservableType


class SsdeepHash(Observable):
    value: str
    type: str = ObservableType.ssdeep
