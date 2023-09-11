from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class MacAddress(Observable):
    value: str
    type: ObservableType = ObservableType.mac_address