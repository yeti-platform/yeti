from core.schemas.observable import Observable
from core.schemas.observable import ObservableType

class ASN(Observable):
    value: str
    type: ObservableType = ObservableType.asn
    country: str = None
    description: str = None
    