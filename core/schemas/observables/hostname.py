from core.schemas import observable


class Hostname(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.hostname