from core.schemas import observable


class Path(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.path