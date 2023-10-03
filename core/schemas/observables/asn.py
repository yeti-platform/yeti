from core.schemas.observable import Observable
from core.schemas.observable import ObservableType
from typing import Literal,ClassVar

class ASN(Observable):
    value: str
    type:  Literal['asn']= ObservableType.asn
    country: str | None = None
    description: str | None = None
