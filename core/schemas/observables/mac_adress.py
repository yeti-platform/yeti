from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal
class MacAddress(Observable):
    value: str
    type: Literal['macaddress'] = ObservableType.mac_address
