from core.schemas import observable


class Url(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.url