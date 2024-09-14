from core.schemas import observable


class IPv4(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.ipv4
