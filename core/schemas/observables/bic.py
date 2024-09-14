from core.schemas import observable


class BIC(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.bic
