from core.schemas import observable


class SHA256(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.sha256
