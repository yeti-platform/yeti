from typing import Literal

from core.schemas import observable


class NamedPipe(observable.Observable):
    type: Literal[observable.ObservableType.named_pipe] = observable.ObservableType.named_pipe


observable.TYPE_MAPPING[observable.ObservableType.named_pipe] = NamedPipe
