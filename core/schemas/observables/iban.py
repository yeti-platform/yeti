from core.schemas import observable


class IBAN(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.iban