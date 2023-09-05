from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class SHA1(Observable):
    value: str
    type: ObservableType = ObservableType.sha1