from core.schemas import observable


class Email(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.email
