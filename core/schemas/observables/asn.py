from typing import Literal

from core.schemas import observable


class ASN(observable.Observable):
    type: Literal["asn"] = "asn"
    country: str | None = None
    description: str | None = None
