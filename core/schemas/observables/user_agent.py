from typing import Literal

from core.schemas import observable


class UserAgent(observable.Observable):
    type: Literal[observable.ObservableType.user_agent] = (
        observable.ObservableType.user_agent
    )
