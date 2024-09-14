from core.schemas import observable


class CommandLine(observable.Observable):
    type: observable.ObservableType = observable.ObservableType.command_line
