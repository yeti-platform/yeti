from core.schemas import observable


class Mutex(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.mutex