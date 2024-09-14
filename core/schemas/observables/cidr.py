from core.schemas import observable


class CIDR(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.cidr
