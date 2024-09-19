from typing import Literal

import validators

from core.schemas import observable


class IPv6(observable.Observable):
    type: Literal[observable.ObservableType.ipv6] = observable.ObservableType.ipv6

    @staticmethod
    def is_valid(value: str) -> bool:
        return validators.ipv6(value)
