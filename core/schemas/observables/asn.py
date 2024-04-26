from typing import Literal

from core.schemas import observable


class ASN(observable.Observable):
    type: Literal[observable.ObservableType.asn] = observable.ObservableType.asn
    country: str | None = None
    description: str | None = None
    name: str | None = None


observable.TYPE_MAPPING[observable.ObservableType.asn] = ASN
