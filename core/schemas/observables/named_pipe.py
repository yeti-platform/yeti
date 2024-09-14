from core.schemas import observable


class NamedPipe(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.named_pipe