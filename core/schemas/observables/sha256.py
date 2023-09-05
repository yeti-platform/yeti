from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class SHA256(Observable):
    value: str
    type: ObservableType = ObservableType.sha256