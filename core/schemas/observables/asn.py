from core.schemas import observable


class ASN(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.asn
    country: str | None = None
    description: str | None = None