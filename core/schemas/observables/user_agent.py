from typing import Literal

from core.schemas import observable


class UserAgent(observable.Observable):
    type: Literal["user_agent"] = "user_agent"
