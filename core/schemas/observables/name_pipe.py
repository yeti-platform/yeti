from typing import Literal

from core.schemas import observable


class NamePipe(observable.Observable):
    type: Literal[observable.ObservableType.name_pipe] = observable.ObservableType.name_pipe


observable.TYPE_MAPPING[observable.ObservableType.name_pipe] = NamePipe
