from core.schemas import observable


class IPv6(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.ipv6
