from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class MD5(Observable):
    value: str
    type: ObservableType = ObservableType.md5